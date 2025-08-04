import { render, screen } from '@testing-library/react';
import App from './App';

test('renders dashboard text', () => {
  render(<App />);
  const element = screen.getByText(/hello, dashboard/i);
  expect(element).toBeInTheDocument();
});
