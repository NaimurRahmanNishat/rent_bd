// src/redux/api/baseApi.ts
import {
    createApi, 
    fetchBaseQuery,
    type BaseQueryApi,
    type BaseQueryFn,
    type FetchArgs,
    type FetchBaseQueryError,
} from '@reduxjs/toolkit/query/react';
import { Mutex } from 'async-mutex';
import { logoutAction } from '../features/auth/authSlice';
import { readCsrfCookie } from '@/utils/cookie';
import { getBaseUrl } from '@/utils/getBaseUrl';


const mutex = new Mutex();
const csrfMutex = new Mutex();

const AUTH_FREE_URLS = new Set([
    'auth/login/',
    'auth/refresh-token/',
    'auth/register/',
    'auth/verify-otp/',
    'auth/resend-otp/',
    'auth/forgot-password/',
    'auth/reset-password/',
    'auth/csrf/',
    'auth/google/',
]);

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function getRequestUrl(args: string | FetchArgs): string {
    return typeof args === 'string' ? args : args.url;
}

function getRequestMethod(args: string | FetchArgs): string {
    return typeof args === 'string' ? 'GET' : (args.method ?? 'GET').toUpperCase();
}

const baseQuery = fetchBaseQuery({
    baseUrl: `${getBaseUrl()}/api/`,
    prepareHeaders: (headers) => {
        const csrfToken = readCsrfCookie();
        if (csrfToken) {
            headers.set('X-CSRFToken', csrfToken);
        }
        return headers;
    },
    credentials: 'include',
});

async function ensureCsrfCookie(api: BaseQueryApi, extraOptions: object = {}) {
    if (readCsrfCookie()) return;

    await csrfMutex.waitForUnlock();
    if (readCsrfCookie()) return;

    const release = await csrfMutex.acquire();
    try {
        if (!readCsrfCookie()) {
            await baseQuery({ url: 'auth/csrf/' }, api, extraOptions);
        }
    } finally {
        release();
    }
}

async function refreshCsrfCookie(api: BaseQueryApi, extraOptions: object = {}) {
    const release = await csrfMutex.acquire();
    try {
        await baseQuery({ url: 'auth/csrf/' }, api, extraOptions);
    } finally {
        release();
    }
}

const baseQueryWithReauth: BaseQueryFn<string | FetchArgs, unknown, FetchBaseQueryError> = async (args, api, extraOptions) => {
    const method = getRequestMethod(args);
    const url = getRequestUrl(args);

    if (UNSAFE_METHODS.has(method) && url !== 'auth/csrf/') {
        await ensureCsrfCookie(api, extraOptions ?? {});
    }

    await mutex.waitForUnlock();
    let result = await baseQuery(args, api, extraOptions);

    if (result.error && result.error.status === 403 && UNSAFE_METHODS.has(method) && url !== 'auth/csrf/' && !(extraOptions as { _csrfRetried?: boolean } | undefined)?._csrfRetried) {
        await refreshCsrfCookie(api, extraOptions ?? {});
        result = await baseQuery(args, api, { ...(extraOptions ?? {}), _csrfRetried: true });
    }

    if (result.error && result.error.status === 401 && !AUTH_FREE_URLS.has(url)) {
        if (!mutex.isLocked()) {
            const release = await mutex.acquire();
            try {
                const refreshResult = await baseQuery(
                    { url: 'auth/refresh-token/', method: 'POST' },
                    api,
                    extraOptions
                );
                if (!refreshResult.error) {
                    result = await baseQuery(args, api, extraOptions);
                } else {
                    api.dispatch(logoutAction());
                }
            } finally {
                release();
            }
        } else {
            await mutex.waitForUnlock();
            result = await baseQuery(args, api, extraOptions);
        }
    }
    return result;
};

export const baseApi = createApi({
    reducerPath: 'baseApi',
    baseQuery: baseQueryWithReauth,
    tagTypes: ['User', 'Auth'],
    endpoints: () => ({}),
});
