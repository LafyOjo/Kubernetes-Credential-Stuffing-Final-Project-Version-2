import React from 'react';

export default function InfoCard({ title, icon, children }) {
  return (
    <div className="bg-gray-800 p-6 rounded-xl shadow-lg h-full">
      <div className="flex items-center gap-3 mb-4">
        <div className="bg-blue-900/50 p-2 rounded-full">{icon}</div>
        <h2 className="text-xl font-semibold">{title}</h2>
      </div>
      <div>{children}</div>
    </div>
  );
}
