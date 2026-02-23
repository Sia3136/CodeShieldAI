import React from 'react';
import { Shield } from 'lucide-react';

const Logo = () => {
  return (
    <div className="relative w-16 h-16 flex items-center justify-center">
      {/* Animated gradient background */}
      <div className="absolute inset-0 bg-gradient-to-br from-blue-500 via-cyan-500 to-purple-500 rounded-xl animate-pulse" />

      {/* Shield icon */}
      <Shield className="relative w-10 h-10 text-white drop-shadow-lg" strokeWidth={2.5} />
    </div>
  );
};

export default Logo;