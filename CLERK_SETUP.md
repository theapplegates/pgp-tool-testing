# Clerk Authentication Setup

This app now uses Clerk for authentication. Follow these steps to set it up:

## 1. Create a Clerk Account

1. Go to [https://clerk.com](https://clerk.com)
2. Sign up for a free account
3. Create a new application

## 2. Get Your Publishable Key

1. In your Clerk dashboard, go to **API Keys**
2. Copy your **Publishable Key** (starts with `pk_test_` or `pk_live_`)

## 3. Configure Environment Variables

1. Open the `.env.local` file in the project root
2. Replace `your_publishable_key_here` with your actual Clerk Publishable Key:

```
VITE_CLERK_PUBLISHABLE_KEY=pk_test_your_actual_key_here
```

## 4. Configure Authentication Methods

By default, Clerk supports:
- Email/Password
- Email Magic Links
- Social logins (Google, GitHub, etc.)

To configure which methods are available:

1. In your Clerk dashboard, go to **User & Authentication** → **Email, Phone, Username**
2. Enable/disable authentication methods as needed
3. For username/password: Enable **Username** and **Password**

## 5. Run the App

```bash
npm run dev
```

The app will now require authentication before users can access the PGP tools.

## Features

- ✅ Username/Password authentication
- ✅ Protected routes - only authenticated users can access crypto tools
- ✅ User profile management via UserButton
- ✅ Sign out functionality
- ✅ Dark mode support

## Troubleshooting

If you see "Missing Clerk Publishable Key" error:
- Make sure `.env.local` exists in the project root
- Verify the key starts with `pk_test_` or `pk_live_`
- Restart the dev server after adding the key

For more help, visit [Clerk Documentation](https://clerk.com/docs)
