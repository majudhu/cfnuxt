import type { SessionConfig } from 'h3';
import { z } from 'zod';

const loginSchema = z.object({ name: z.string(), password: z.string() });

const decoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
const encoder = new TextEncoder();
let memory8: Uint8Array;
let memory32: Int32Array;

export type LoginSchema = z.input<typeof loginSchema>;

export default defineLazyEventHandler(async function () {
  // @ts-expect-error TODO: https://github.com/nuxt/nuxt/issues/14131
  const wasm = await import('~/server/rs_wasm_argon2_bg.wasm');

  return defineEventHandler(async function (event) {
    const data = await readValidatedBody(event, loginSchema.parse);

    const salt = crypto.getRandomValues(new Uint8Array(16));

    const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);

    wasm.hash(
      retptr,
      ...passStringToWasm(data.password, wasm),
      ...passArray8ToWasm(salt, wasm)
    );

    // https://github.com/KhronosGroup/KTX-Software/issues/371#issuecomment-822299324
    // https://stackoverflow.com/a/54062241
    if (memory8.byteLength === 0) memory8 = new Uint8Array(wasm.memory.buffer);

    memory32 ??= new Int32Array(wasm.memory.buffer);
    const ptr = memory32[retptr / 4 + 0] >>> 0;
    const len = memory32[retptr / 4 + 1];
    const hash = decoder.decode(memory8.subarray(ptr, ptr + len));
    wasm.__wbindgen_free(ptr, len, 1);

    return { name: data.name, hash };
  });
});

// if (data.name && (await verify(hash1234, data.password))) {
//   const session = await useSession(event, sessionConfig);
//   await session.update({ name: data.name });
//   return { name: data.name };x
// } else throw createError({ statusCode: 401, statusMessage: 'Unauthorized' });

const hash1234 =
  '$argon2id$v=19$m=19456,t=2,p=1$pd3RjIrn9Kc7R1HApNjAXQ$I174Yrm2BAU2fBI2ydeqk1QGyefxBq/O0uo+P5llZfY';

const sessionConfig: SessionConfig = {
  password: 'secretsecretsecretsecretsecretse',
};

function passStringToWasm(string: string, wasm: any) {
  const len = string.length * 4;
  let ptr = wasm.__wbindgen_malloc(len, 1) >>> 0;
  memory8 ??= new Uint8Array(wasm.memory.buffer);
  const view = memory8.subarray(ptr, ptr + len);
  const { written } = encoder.encodeInto(string, view);
  ptr = wasm.__wbindgen_realloc(ptr, len, written, 1) >>> 0;
  return [ptr, written];
}

function passArray8ToWasm(array: Uint8Array, wasm: any) {
  const len = array.length;
  let ptr = wasm.__wbindgen_malloc(len, 1) >>> 0;
  memory8 ??= new Uint8Array(wasm.memory.buffer);
  memory8.set(array, ptr);
  return [ptr, len];
}
