/** @type {import('next').NextConfig} */
const backendBase = (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8765').replace(/\/$/, '');

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${backendBase}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
