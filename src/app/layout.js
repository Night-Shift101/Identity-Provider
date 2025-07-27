/**
 * Root Layout Component
 * Main layout for the IdP application
 * @author IdP System
 */

// TODO: SECURITY-Critical - Implement Content Security Policy headers to prevent XSS attacks
import { Inter } from 'next/font/google';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata = {
  title: 'Identity Provider - Secure Account Management',
  description: 'Comprehensive identity provider with SSO, MFA, and device management',
  keywords: 'identity provider, SSO, authentication, MFA, security',
  authors: [{ name: 'IdP System' }],
};

export const viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <meta name="theme-color" content="#2563eb" />
        <meta name="mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="default" />
        <meta name="apple-mobile-web-app-title" content="IdP" />
        <meta name="application-name" content="Identity Provider" />
        <meta name="msapplication-TileColor" content="#2563eb" />
        <meta name="msapplication-config" content="/browserconfig.xml" />
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="icon" href="/favicon.ico" />
        <link rel="apple-touch-icon" href="/icons/icon.svg" />
        <link rel="manifest" href="/manifest.json" />
      </head>
            <body className={inter.className}>
        {/* TODO: FUNCTIONALITY - Implement React Error Boundary for better error handling */}
        {children}
        <div id="root" className="min-h-screen">
          {children}
        </div>
        
        {/* Toast notification container */}
        <div id="toast-container" className="fixed top-4 right-4 z-50 space-y-2">
          {/* Toast notifications will be rendered here */}
        </div>

        {/* Modal container */}
        <div id="modal-container" className="relative z-40">
          {/* Modals will be rendered here */}
        </div>

        {/* Loading overlay */}
        <div id="loading-overlay" className="fixed inset-0 bg-black bg-opacity-50 z-50 hidden items-center justify-center">
          <div className="bg-white rounded-lg p-6 max-w-sm mx-4">
            <div className="flex items-center space-x-4">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              <div className="text-gray-700">
                <div className="font-medium">Processing...</div>
                <div className="text-sm text-gray-500">Please wait a moment</div>
              </div>
            </div>
          </div>
        </div>

        {/* External error handling script - safer than dangerouslySetInnerHTML */}
        <script src="/js/error-handler.js"></script>
      </body>
    </html>
  );
}
