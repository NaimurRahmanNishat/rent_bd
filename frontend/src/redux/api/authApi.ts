// src/redux/api/authApi.ts
import { baseApi } from "./baseApi";


const authApi = baseApi.injectEndpoints({
    endpoints: (builder) => ({
        login: builder.mutation({
            query: (credentials) => ({
                url: 'auth/login/',
                method: 'POST',
                body: credentials,
            }),
        }),
        register: builder.mutation({
            query: (credentials) => ({
                url: 'auth/register/',
                method: 'POST',
                body: credentials,
            }),
        }),
        verifyOtp: builder.mutation({
            query: (credentials) => ({
                url: 'auth/verify-otp/',
                method: 'POST',
                body: credentials,
            }),
        }),
        resendOtp: builder.mutation({
            query: (credentials) => ({
                url: 'auth/resend-otp/',
                method: 'POST',
                body: credentials,
            }),
        }),
        forgotPassword: builder.mutation({
            query: (credentials) => ({
                url: 'auth/forgot-password/',
                method: 'POST',
                body: credentials,
            }),
        }),
        resetPassword: builder.mutation({
            query: (credentials) => ({
                url: 'auth/reset-password/',
                method: 'POST',
                body: credentials,
            }),
        }),
        google: builder.mutation({
            query: (credentials) => ({
                url: 'auth/google/',
                method: 'POST',
                body: credentials,
            }),
        }),
    }),
})

export const {
    useLoginMutation,
    useRegisterMutation,
    useVerifyOtpMutation,
    useResendOtpMutation,
    useForgotPasswordMutation,
    useResetPasswordMutation,
    useGoogleMutation,
} = authApi
export default authApi;
