/* A D1-shaped facade over node:sqlite, so the quota tests run the REAL SQL —
   including `INSERT … ON CONFLICT … RETURNING`, which is the one statement the
   whole cost-control story depends on. A hand-written fake object would have
   happily "passed" a query D1 would reject. */
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';

class Stmt {
  constructor(db, sql){ this.db = db; this.sql = sql; this.args = []; }
  bind(...args){ this.args = args; return this; }
  _prep(){ return this.db.prepare(this.sql); }
  async first(){
    const r = this._prep().get(...this.args);
    return r === undefined ? null : r;
  }
  async run(){
    const r = this._prep().run(...this.args);
    return { success: true, meta: { changes: r.changes, last_row_id: r.lastInsertRowid } };
  }
  async all(){ return { results: this._prep().all(...this.args), success: true }; }
}

export function makeD1(schemaPath = new URL('./schema.sql', import.meta.url)){
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(schemaPath, 'utf8'));
  return {
    prepare: sql => new Stmt(db, sql),
    _raw: db,
    _close: () => db.close(),
  };
}
