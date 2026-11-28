// src/utils/getBaseUrl.ts

const isDev = process.env.NODE_ENV === 'development';
export function getBaseUrl() {
    if (typeof window !== 'undefined') {
        return '';
    }
    if (isDev) {
        return 'http://localhost:3000';
    }
    return process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3000';
};
