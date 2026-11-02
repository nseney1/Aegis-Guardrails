import {describe, test, expect} from 'vitest';
import {value} from '../src/app';
describe('acceptance', () => { test('correct value', () => { expect(value()).toBe(2); }); });
