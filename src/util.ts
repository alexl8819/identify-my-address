import decamelize from 'decamelize';
import camelCase from 'camelcase';

import { Analysis } from './constants';

type KeyValueObject = { [key: string]: any };

export function decamelizeObject (object: KeyValueObject): Record<string, string> {
  for (const [key, value] of Object.entries(object)) {
    delete object[key];
    const decamelizedKey: string = decamelize(key);
    object[decamelizedKey] = value;
  }
  return object;
}

export function camelizeObject (object: KeyValueObject): Analysis {
  for (const [key, value] of Object.entries(object)) {
    delete object[key];
    const cc: string = camelCase(key);
    object[cc] = value;
  }
  return object as Analysis;
}
