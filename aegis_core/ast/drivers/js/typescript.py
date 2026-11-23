"""Type positions for the JavaScript and TypeScript lexer: where a `{` after a TS type operator opens a type."""
from __future__ import annotations

__all__ = ['TypePositions']
# Punctuators that may stand between the brackets of type arguments; `=` only in type parameters.
_TYPE_ARGUMENT_PUNCTUATORS = frozenset((',', '.', '|', '&', '(', ')', '[', ']', '{', '}', ':', '?', '=>', '...', '-', '<', '>', '>>', '>>>'))


class TypePositions:
    """TS type position checks; the token stream and annotation state they read live on the lexer."""

    def type_operator_brace(self):
        """Whether `{` right after `as`, `satisfies`, `extends`, `readonly` or `is` on its line opens a type literal.

        Only in a type position: the word may also be an identifier (`x = is { … }`, `x = y; readonly { … }`)
        or a property name, or follow a line break after ASI, and the `{` then opens a block whose calls count.
        """
        tokens, word, last = self.tokens, self.previous, len(self.tokens) - 1
        if (not self.typescript or word not in ('as', 'satisfies', 'extends', 'readonly', 'is') or last < 1
                or tokens[last].value != word or self.line_break(tokens[last].end, self.i)):
            return False
        return self.type_word(last)

    def type_word(self, index):
        """Whether the type operator word at tokens[index] stands in a type position."""
        tokens, word = self.tokens, self.tokens[index].value
        before = tokens[index - 1]
        if word == 'readonly':  # `u: readonly { a: T }[]`, `Array<readonly { … }>`, `type X = readonly { … }[]`
            return (before.value in ('|', '&', '<', '(', ',', '[') or self.annotation_at == index - 1 or self.type_alias_value(index - 1)
                    or index > 1 and before.value in ('as', 'satisfies', 'extends') and self.type_word(index - 1))
        if word == 'is':  # a return type predicate: `(v): v is { … }` or `(v): asserts v is { … }`
            colon = index - (3 if index > 2 and tokens[index - 2].value == 'asserts' else 2)
            return before.kind == 'identifier' and colon > 0 and self.annotation_at == colon and tokens[colon - 1].value == ')'
        # TS never continues `as`, `satisfies` or a conditional type's `extends` across a line break.
        return self.same_line(index - 1) and self.operand_end(index - 1)

    def operand_end(self, index):
        """Whether tokens[index] can end an operand, as before `x as T`."""
        while self.tokens[index].kind == 'punct' and self.tokens[index].value in ('!', '++', '--'):
            if index == 0 or not self.same_line(index - 1):  # a postfix `x!` or `x++`: no line break before it
                return False
            index -= 1
        token = self.tokens[index]
        if token.kind == 'identifier':  # `y as const satisfies { … }`
            return not self.syntax_word(token.value) or token.value == 'const' and index > 0 and self.tokens[index - 1].value == 'as'
        if token.kind != 'punct':
            return token.kind in ('number', 'string', 'regex', 'template_end', 'flat_call', 'flat_object')
        if token.value in ('>', '>>', '>>>'):  # type arguments after a name: `NonNullable<T> extends { … }`
            start = self.type_arguments_start(index)
            return start > 0 and self.tokens[start - 1].kind == 'identifier'
        return token.value == ']' or token.value == ')' and token.role != 'control' or token.value == '}' and token.role in ('object', 'function_expr', 'class_expr')

    def same_line(self, index):
        """Whether no line break separates tokens[index] from the token after it."""
        return not self.line_break(self.tokens[index].end, self.tokens[index + 1].start)

    def type_arguments_start(self, index, parameters=False):
        """The index of the `<` that the `>` at tokens[index] closes, or -1.

        Brackets between them must balance and hold only tokens that type arguments may hold (and `=` in
        type parameters), so `f(a < b) > x` and `a < b` + `x = c > y` are no type argument lists.
        """
        angles = brackets = 0
        for cursor in range(index, max(index - 512, 0) - 1, -1):
            token = self.tokens[cursor]
            value = token.value
            if token.kind == 'punct' and value not in _TYPE_ARGUMENT_PUNCTUATORS and not (parameters and value == '='):
                return -1
            if value in (')', ']', '}'):
                brackets += 1
            elif value in ('(', '[', '{'):
                if not brackets:
                    return -1
                brackets -= 1
            elif not brackets and value in ('>', '>>', '>>>'):
                angles += len(value)
            elif not brackets and value == '<':
                angles -= 1
                if not angles:
                    return cursor
        return -1

    def type_alias_value(self, index):
        """Whether the `=` at tokens[index] starts a type alias value: `type X = …` or `type X<T> = …`."""
        tokens = self.tokens
        name = index - 1
        if tokens[index].value != '=' or name < 1:
            return False
        if tokens[name].value in ('>', '>>', '>>>'):
            name = self.type_arguments_start(name, parameters=True) - 1
        return (name > 0 and tokens[name].kind == 'identifier' and tokens[name - 1].value == 'type' and self.same_line(name - 1)
                and (name < 2 or tokens[name - 2].value not in ('.', '?.')))
