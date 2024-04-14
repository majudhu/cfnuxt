<script setup lang="ts">
import type { FormError, FormSubmitEvent } from '#ui/types';
import type { LoginSchema } from '~/server/api/auth.post';
import type { H3Error } from 'h3';

const state: LoginSchema = reactive({ name: '', password: '' });

function validate(state: LoginSchema) {
  const errors: FormError[] = [];
  if (!state.name) errors.push({ path: 'name', message: 'Required' });
  if (!state.password) errors.push({ path: 'password', message: 'Required' });
  return errors;
}

const loginError = ref('');

async function onSubmit({ data }: FormSubmitEvent<LoginSchema>) {
  loginError.value = '';
  try {
    $fetch('/api/auth', { method: 'POST', body: data });
    const res = await $fetch('/api/auth2', { method: 'POST', body: data });
    if (res) {
      // navigateTo('/');
    }
  } catch (error) {
    if ((error as H3Error).statusCode === 401) {
      loginError.value = 'Invalid credentials';
    }
  }
}
</script>

<template>
  <UForm
    :validate="validate"
    :state="state"
    class="p-10 max-w-sm mx-auto space-y-4"
    @submit="onSubmit"
  >
    <UFormGroup label="Name" name="name">
      <UInput v-model="state.name" />
    </UFormGroup>

    <UFormGroup label="Password" name="password" :error="loginError">
      <UInput v-model="state.password" type="password" />
    </UFormGroup>

    <UButton type="submit">Login</UButton>
  </UForm>
</template>
