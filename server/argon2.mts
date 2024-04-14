const decoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
const encoder = new TextEncoder();

// https://github.com/nuxt/examples/tree/main/examples/experimental/wasm
const wasm: {
  memory: WebAssembly.Memory;
  hash(a: number, b: number, c: number, d: number, e: number): void;
  verify(a: number, b: number, c: number, d: number): number;
  __wbindgen_add_to_stack_pointer(a: number): number;
  __wbindgen_malloc(a: number, b: number): number;
  __wbindgen_realloc(a: number, b: number, c: number, d: number): number;
  __wbindgen_free(a: number, b: number, c: number): void;
  // @ts-expect-error TODO: https://github.com/nuxt/nuxt/issues/14131
} = await import('./rs_wasm_argon2_bg.wasm');

let _Uint8Memory: Uint8Array;
function getUInt8Memory() {
  if (!_Uint8Memory || _Uint8Memory.buffer.byteLength === 0) {
    _Uint8Memory = new Uint8Array(wasm.memory.buffer);
  }
  return _Uint8Memory;
}

let _Int32Memory: Int32Array;
function getInt32Memory() {
  if (!_Int32Memory || _Int32Memory.buffer.byteLength === 0) {
    _Int32Memory = new Int32Array(wasm.memory.buffer);
  }
  return _Int32Memory;
}

export function hash(password: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);

  wasm.hash(
    retptr,
    ...passStringToWasm(password, wasm),
    ...passArray8ToWasm(salt, wasm)
  );

  const hash = getStringFromWasm(retptr);

  return hash;
}

export function verify(hash: string, password: string) {
  const result = wasm.verify(
    ...passStringToWasm(hash, wasm),
    ...passStringToWasm(password, wasm)
  );
  return result !== 0;
}

function getStringFromWasm(retptr: number): string {
  const memory = getInt32Memory();
  const ptr = memory[retptr / 4 + 0] >>> 0;
  const len = memory[retptr / 4 + 1];
  const string = decoder.decode(getUInt8Memory().subarray(ptr, ptr + len));
  wasm.__wbindgen_free(ptr, len, 1);
  return string;
}

function passStringToWasm(string: string, wasm: any): [number, number] {
  const len = string.length * 4;
  let ptr = wasm.__wbindgen_malloc(len, 1) >>> 0;
  const view = getUInt8Memory().subarray(ptr, ptr + len);
  const { written } = encoder.encodeInto(string, view);
  ptr = wasm.__wbindgen_realloc(ptr, len, written, 1) >>> 0;
  return [ptr, written];
}

function passArray8ToWasm(array: Uint8Array, wasm: any): [number, number] {
  const len = array.length;
  let ptr = wasm.__wbindgen_malloc(len, 1) >>> 0;
  getUInt8Memory().set(array, ptr);
  return [ptr, len];
}
