// Global error handler for unhandled promise rejections
window.addEventListener('unhandledrejection', function(event) {
  console.error('Unhandled promise rejection:', event.reason);
  // You could send this to an error reporting service
});

// Global error handler
window.addEventListener('error', function(event) {
  console.error('Global error:', event.error);
  // You could send this to an error reporting service
});
