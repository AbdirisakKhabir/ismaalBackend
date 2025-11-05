const { execSync } = require('child_process');
const path = require('path');

console.log('🚀 Starting ISMAAL Backend Server...\n');

try {
  // Check if Prisma client is generated
  console.log('📦 Checking Prisma setup...');
  execSync('npx prisma generate', { stdio: 'inherit', cwd: __dirname });
  
  // Start the server
  console.log('🌐 Starting Express server...');
  execSync('node app.js', { stdio: 'inherit', cwd: __dirname });
} catch (error) {
  console.error('❌ Error starting server:', error.message);
  process.exit(1);
}
