import type { SessionConfig } from 'h3';
import { z } from 'zod';

const loginSchema = z.object({ name: z.string(), password: z.string() });

const encoder = new TextEncoder();
let memory8: Uint8Array;

export type LoginSchema = z.input<typeof loginSchema>;

export default defineLazyEventHandler(async function () {
  // @ts-expect-error TODO: https://github.com/nuxt/nuxt/issues/14131
  const wasm = await import('~/server/rs_wasm_argon2_bg.wasm');

  return defineEventHandler(async function (event) {
    const data = await readValidatedBody(event, loginSchema.parse);

    const isMatch =
      wasm.verify(
        ...passStringToWasm(data.password, wasm),
        ...passStringToWasm(hash1234, wasm)
      ) !== 0;

    // https://github.com/KhronosGroup/KTX-Software/issues/371#issuecomment-822299324
    // https://stackoverflow.com/a/54062241
    if (memory8.byteLength === 0) memory8 = new Uint8Array(wasm.memory.buffer);

    return { name: data.name, isMatch };
  });
});

// if (data.name && (await verify(hash1234, data.password))) {
//   const session = await useSession(event, sessionConfig);
//   await session.update({ name: data.name });
//   return { name: data.name };x
// } else throw createError({ statusCode: 401, statusMessage: 'Unauthorized' });

const sessionConfig: SessionConfig = {
  password: 'secretsecretsecretsecretsecretse',
};

const hash1234 =
  '$argon2id$v=19$m=19456,t=2,p=1$Nf+RjqJ/2mIUFDju26YugQ$XwXP7czvDKbaaXYRMY8fsH6qp8ZaP+jiMzKign9e0Pg';

function passStringToWasm(string: string, wasm: any) {
  const len = string.length * 4;
  let ptr = wasm.__wbindgen_malloc(len, 1) >>> 0;
  memory8 ??= new Uint8Array(wasm.memory.buffer);
  const view = memory8.subarray(ptr, ptr + len);
  const { written } = encoder.encodeInto(string, view);
  ptr = wasm.__wbindgen_realloc(ptr, len, written, 1) >>> 0;
  return [ptr, written];
}
