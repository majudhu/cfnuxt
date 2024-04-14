// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  devtools: { enabled: true },

  nitro: {
    preset: 'cloudflare-pages',

    experimental: { wasm: true },
  },

  modules: ['nitro-cloudflare-dev', '@nuxt/ui'],
});
