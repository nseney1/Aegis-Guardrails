"""Package-internal keys and late-bound class identities for native authority.

These objects coordinate trusted installed modules in the host process. No
key or registration is carried on the wire or accepted from a model child.
"""

from weakref import WeakValueDictionary

from aegis_core.team_native_wire import HostAuthorityError

__all__ = [
    "BOUND_INITIAL_KEY", "GUARD_KEY", "LIVE_KEY", "RESERVATION_KEY",
    "NativeIdentities", "NATIVE_IDENTITIES",
]

RESERVATION_KEY = object()
GUARD_KEY = object()
BOUND_INITIAL_KEY = object()
LIVE_KEY = object()


class NativeIdentities:
    """Bind each role once, and track live bindings by identity without owning them."""

    def __init__(self):
        self._types = {}
        self._bindings = WeakValueDictionary()

    def bind_type(self, name, implementation):
        """Called by the defining installed module once its class exists."""
        if type(name) is not str or name not in ("binding", "invocation") or not isinstance(implementation, type):
            raise HostAuthorityError("ROLE_OPERATION_FORBIDDEN", "invalid native class identity")
        if self._types.setdefault(name, implementation) is not implementation:
            raise HostAuthorityError("ROLE_OPERATION_FORBIDDEN", "native class identity is already bound")

    def is_instance(self, name, value):
        return type(value) is self._types.get(name)

    def owns_binding(self, binding):
        return (self.is_instance("binding", binding)
                and self._bindings.get(id(binding)) is binding)

    def register_binding(self, key, binding):
        if key is not LIVE_KEY or not self.is_instance("binding", binding):
            raise HostAuthorityError("ROLE_OPERATION_FORBIDDEN", "registration requires an owned binding")
        binding.require_owner_process()
        self._bindings[id(binding)] = binding

    def discard_binding(self, key, binding):
        if key is not LIVE_KEY or not self.is_instance("binding", binding):
            raise HostAuthorityError("ROLE_OPERATION_FORBIDDEN", "registration requires an owned binding")
        binding.require_owner_process()
        self._bindings.pop(id(binding), None)


NATIVE_IDENTITIES = NativeIdentities()
