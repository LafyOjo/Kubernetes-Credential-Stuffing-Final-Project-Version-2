import React from 'react';
import { ShoppingCart } from 'lucide-react';
import InfoCard from './InfoCard';

export default function ShopStatsCard({ cart, isBackendConnected }) {
  const itemCount = isBackendConnected ? cart.length : 'N/A';
  const totalValue = isBackendConnected ? cart.reduce((sum, item) => sum + item.price, 0) : 0;

  return (
    <InfoCard title="Demo Shop Status" icon={<ShoppingCart />}>
      <div className="space-y-2">
        <div>
          <p className="text-gray-400">Items in Cart</p>
          <p className="text-2xl font-bold">{itemCount}</p>
        </div>
        <div>
          <p className="text-gray-400">Total Cart Value</p>
          <p className="text-2xl font-bold">${isBackendConnected ? totalValue.toFixed(2) : '0.00'}</p>
        </div>
        <p className="text-xs text-gray-500 pt-2">
          {isBackendConnected
            ? 'This is the data at risk of being exposed in a successful credential stuffing attack.'
            : 'Connect to the backend to see live cart data.'}
        </p>
      </div>
    </InfoCard>
  );
}
