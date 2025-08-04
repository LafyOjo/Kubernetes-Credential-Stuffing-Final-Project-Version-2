import React, { useState, useEffect, useRef } from 'react';
import { Shield, User, LogOut, AlertTriangle, BarChart, KeyRound, PlayCircle, Info, XCircle, CheckCircle, Database, FileWarning, PieChart, ShoppingCart } from 'lucide-react';
import { Chart, registerables } from 'chart.js';
import InfoCard from './components/InfoCard';
import ShopStatsCard from './components/ShopStatsCard';

// Register Chart.js components
Chart.register(...registerables);

// --- MOCK DATA & CONFIGURATION ---
const ACCOUNTS = {
  alice: {
    username: 'alice@example.com', // Use email for login
    password: 'password123',
    securityLevel: 'Weaker Security',
    description: 'This account has basic password protection and is vulnerable to repeated login attempts. It does not use advanced security like JWTs.',
    token: null,
    securityScore: 25,
  },
  ben: {
    username: 'ben@example.com', // Use email for login
    password: 'strongPassword!@#',
    securityLevel: 'Stronger Security (JWT-based)',
    description: 'This account uses a stronger password and is protected by a JSON Web Token (JWT) upon login, simulating a more secure Zero-Trust approach.',
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiZW5AZXhhbXBsZS5jb20iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE2NzA4MjU2MDB9.some_signature_for_ben',
    securityScore: 90,
  },
};

const ROCKYOU_PASSWORDS = [
  '123456', 'password', '123456789', '12345678', '12345', 'qwerty', '1234567', 'sunshine', 'iloveyou', 'dragon', 'princess', 'monkey', 'shadow', 'football'
];

const mockHash = (password) => {
    let hash = 0;
    for (let i = 0; i < password.length; i++) {
        const char = password.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash |= 0;
    }
    return 'mock_sha256$' + Math.abs(hash).toString(16);
};


// --- MAIN APP COMPONENT ---
export default function App() {
  const [view, setView] = useState('login');
  const [user, setUser] = useState(null);
  const [error, setError] = useState('');

  // --- Dashboard State ---
  const [loginAttempts, setLoginAttempts] = useState([]);
  const [blockedAttempts, setBlockedAttempts] = useState(0);
  const [attackStatus, setAttackStatus] = useState('idle');
  const [attackResults, setAttackResults] = useState(null);
const [compromisedAccount, setCompromisedAccount] = useState(null);
const [shopCart, setShopCart] = useState([]);
const [isBackendConnected, setIsBackendConnected] = useState(true); // Assume connected initially

// --- SIMULATED DATABASE ---
const [databaseLogs, setDatabaseLogs] = useState([]);

const saveLogToDatabase = (log) => {
  setDatabaseLogs(prevLogs => [...prevLogs, log]);
};
  
  const fetchShopCart = async (token) => {
      if (!token || !isBackendConnected) return;
      try {
          const response = await fetch(`http://localhost:8000/shop/cart`, {
              headers: { 'Authorization': `Bearer ${token}` }
          });
          if (response.ok) {
              const cartData = await response.json();
              setShopCart(cartData);
          } else {
              setShopCart([]);
          }
      } catch (err) {
          console.error("Failed to fetch shop cart:", err);
          setShopCart([]);
      }
  };

  useEffect(() => {
      let interval;
      if (user?.token) {
          fetchShopCart(user.token);
          interval = setInterval(() => fetchShopCart(user.token), 5000);
      }
      return () => clearInterval(interval);
  }, [user, isBackendConnected]);


  // --- API Simulation ---
  const mockApiLogin = async (username, password) => {
    let attemptResult = { user: username, status: 'failed', timestamp: new Date().toISOString() };
    const account = Object.values(ACCOUNTS).find(acc => acc.username === username);

    try {
        // Attempt to connect to the real backend
        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);
        const response = await fetch(`http://localhost:8000/auth/login`, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: formData,
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Login failed');
        }
        
        const loginData = await response.json();
        setIsBackendConnected(true);
        setLoginAttempts(prev => [...prev, { ...attemptResult, status: 'success' }]);
        saveLogToDatabase({ ...attemptResult, status: 'success' });
        return { success: true, user: {...account, token: loginData.access_token} };

    } catch (err) {
        // *** FALLBACK LOGIC ***
        console.warn("Backend fetch failed. Falling back to client-side simulation.", err.message);
        setIsBackendConnected(false); // Mark backend as disconnected

        if (!account) {
            setLoginAttempts(prev => [...prev, attemptResult]);
            saveLogToDatabase(attemptResult);
            return { success: false, message: 'User not found (offline mode).' };
        }
    
        if (password === account.password) {
            attemptResult.status = 'success';
            setLoginAttempts(prev => [...prev, attemptResult]);
            saveLogToDatabase(attemptResult);
            // Return mock user object with a fake token for UI purposes
            return { success: true, user: {...account, token: 'fake-offline-token'} };
        }
        
        setLoginAttempts(prev => [...prev, attemptResult]);
        saveLogToDatabase(attemptResult);
        return { success: false, message: 'Invalid credentials (offline mode).' };
    }
  };

  // --- Handlers ---
  const handleLogin = async (username, password) => {
    setError('');
    const result = await mockApiLogin(username, password);
    if (result.success) {
      setUser(result.user);
      await fetchShopCart(result.user.token);
      setView('dashboard');
    } else {
      setError(result.message);
    }
  };

  const handleLogout = () => {
    setUser(null);
    setView('login');
    setAttackStatus('idle');
    setAttackResults(null);
    setCompromisedAccount(null);
    setShopCart([]);
  };

  const handleAttack = async () => {
    if (!user) return;
    setAttackStatus('running');
    setAttackResults(null);
    setCompromisedAccount(null);
    let successfulLogins = 0;
    let localBlockedAttempts = 0;
    const targetUserAccount = ACCOUNTS[user.username.split('@')[0]];
    const targetUser = targetUserAccount.username;
    const totalAttackAttempts = 50;

    let attackPasswords = [...ROCKYOU_PASSWORDS];
    for (let i = attackPasswords.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [attackPasswords[i], attackPasswords[j]] = [attackPasswords[j], attackPasswords[i]];
    }
    const randomIndex = Math.floor(Math.random() * totalAttackAttempts);
    attackPasswords.splice(randomIndex, 0, targetUserAccount.password);
    attackPasswords = attackPasswords.slice(0, totalAttackAttempts);

    let firstBreach = null;

    for (let i = 0; i < totalAttackAttempts; i++) {
        const passwordGuess = attackPasswords[i];
        await new Promise(res => setTimeout(res, 150));
        let attemptResult = { user: targetUser, status: 'failed', timestamp: new Date().toISOString(), source: 'attack_simulation' };
        const recentFailed = loginAttempts.filter(a => a.user === targetUser && a.status === 'failed' && (new Date() - new Date(a.timestamp) < 10000)).length;
        const rateLimitThreshold = targetUser.startsWith('ben') ? 3 : 5;

        if (recentFailed > rateLimitThreshold) {
            localBlockedAttempts++;
            setBlockedAttempts(prev => prev + 1);
            continue; 
        }

        if (passwordGuess === targetUserAccount.password) {
            attemptResult.status = 'success';
            successfulLogins++;
            
            if (targetUser.startsWith('alice') && !firstBreach) {
                firstBreach = {
                    username: targetUser,
                    password: passwordGuess,
                    passwordHash: mockHash(passwordGuess),
                    timestamp: new Date().toISOString(),
                    attemptNumber: i + 1
                };
            }
        }
        
        setLoginAttempts(prev => [...prev, attemptResult]);
        saveLogToDatabase(attemptResult);
    }

    if (firstBreach && isBackendConnected) {
        try {
            const formData = new URLSearchParams();
            formData.append('username', firstBreach.username);
            formData.append('password', firstBreach.password);
            const loginResponse = await fetch(`http://localhost:8000/auth/login`, {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: formData,
            });
            const loginData = await loginResponse.json();
            const attackerToken = loginData.access_token;

            const cartResponse = await fetch(`http://localhost:8000/shop/cart`, {
                headers: { 'Authorization': `Bearer ${attackerToken}` }
            });
            const cartData = await cartResponse.json();
            setCompromisedAccount({ ...firstBreach, stolenCart: cartData });

        } catch (err) {
            console.error("Data exfiltration failed:", err);
            setCompromisedAccount(firstBreach);
        }
    } else if (firstBreach) {
        // If backend is not connected, still show the breach but with mock cart data
        console.warn("Data exfiltration step skipped: Backend not available. Showing mock cart data.");
        setCompromisedAccount({ ...firstBreach, stolenCart: [{name: "Mock Sock", price: 9.99}] });
    }

    setAttackStatus('finished');
    setAttackResults({ total: totalAttackAttempts, success: successfulLogins, blocked: localBlockedAttempts });
  };

  return (
    <div className="bg-gray-900 text-white min-h-screen font-sans flex flex-col items-center justify-center p-4">
      {view === 'login' && <LoginScreen onLogin={handleLogin} error={error} />}
      {view === 'dashboard' && user && (
        <Dashboard
          user={user}
          onLogout={handleLogout}
          loginAttempts={loginAttempts}
          blockedAttempts={blockedAttempts}
          onAttack={handleAttack}
          attackStatus={attackStatus}
          attackResults={attackResults}
          compromisedAccount={compromisedAccount}
          databaseLogCount={databaseLogs.length}
          shopCart={shopCart}
          isBackendConnected={isBackendConnected}
        />
      )}
    </div>
  );
}

// --- LOGIN SCREEN COMPONENT ---
const LoginScreen = ({ onLogin, error }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const handleSubmit = (e) => { e.preventDefault(); onLogin(username, password); };

  return (
    <div className="w-full max-w-md">
      <div className="text-center mb-8">
        <Shield className="mx-auto h-16 w-16 text-blue-400" />
        <h1 className="text-4xl font-bold mt-4">APIShield+</h1>
        <p className="text-gray-400 mt-2">API Security Dashboard</p>
      </div>
      <div className="bg-gray-800 p-8 rounded-xl shadow-2xl">
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-gray-300 text-sm font-bold mb-2" htmlFor="username">Email Address</label>
            <input id="username" type="email" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="alice@example.com or ben@example.com" className="w-full bg-gray-700 border border-gray-600 rounded-lg py-3 px-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required />
          </div>
          <div className="mb-6">
            <label className="block text-gray-300 text-sm font-bold mb-2" htmlFor="password">Password</label>
            <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" className="w-full bg-gray-700 border border-gray-600 rounded-lg py-3 px-4 text-white focus:outline-none focus:ring-2 focus:ring-blue-500" required />
          </div>
          {error && <div className="bg-red-900 border border-red-700 text-red-200 px-4 py-3 rounded-lg relative mb-4 text-center"><span className="block sm:inline">{error}</span></div>}
          <button type="submit" className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg transition duration-300 ease-in-out transform hover:scale-105">Login</button>
        </form>
        <div className="text-center mt-6 text-sm text-gray-500"><p>Default accounts have been created for you.</p></div>
      </div>
    </div>
  );
};

// --- DASHBOARD COMPONENT ---
const Dashboard = ({ user, onLogout, loginAttempts, blockedAttempts, onAttack, attackStatus, attackResults, compromisedAccount, databaseLogCount, shopCart, isBackendConnected }) => {
  return (
    <div className="w-full max-w-7xl mx-auto">
      <header className="flex justify-between items-center mb-8 p-4 bg-gray-800/50 rounded-xl">
        <div className="flex items-center gap-3">
          <Shield className="h-10 w-10 text-blue-400" />
          <div><h1 className="text-3xl font-bold">APIShield+ Dashboard</h1><p className="text-gray-400">Real-time API Threat Monitoring</p></div>
        </div>
        <div className="flex items-center gap-4">
            <div className="text-right"><p className="font-semibold">{user.username}</p><p className="text-xs text-gray-400">{user.securityLevel}</p></div>
          <button onClick={onLogout} className="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg flex items-center gap-2 transition duration-300"><LogOut size={18} /> Logout</button>
        </div>
      </header>
      
      {!isBackendConnected && (
        <div className="bg-yellow-900/70 border-2 border-yellow-500 p-4 rounded-xl shadow-lg mb-8 text-center">
            <h2 className="text-lg font-bold text-white flex items-center justify-center gap-2"><AlertTriangle/>Offline Mode Active</h2>
            <p className="text-yellow-200 text-sm">Could not connect to the backend. Running in client-side simulation mode.</p>
        </div>
      )}

      <main className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-1 flex flex-col gap-8">
          <InfoCard title="Account Security Profile" icon={<User />}><p className="font-bold text-lg text-blue-300">{user.username}</p><p className="text-sm font-semibold text-yellow-400 mb-2">{user.securityLevel}</p><p className="text-gray-300 text-sm">{user.description}</p>{user.token && <div className="mt-4"><p className="text-xs font-mono bg-gray-900 p-2 rounded-md break-all border border-gray-700"><span className="font-bold text-green-400">JWT: </span>{user.token}</p></div>}</InfoCard>
          <ShopStatsCard cart={shopCart} isBackendConnected={isBackendConnected} />
          <PieChartCard user={user} />
          <AttackCard onAttack={onAttack} status={attackStatus} results={attackResults} user={user} />
        </div>
        <div className="lg:col-span-2 flex flex-col gap-8">
          {compromisedAccount && <CompromisedCredentialCard account={compromisedAccount} />}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <StatCard title="Total Login Attempts" value={loginAttempts.length} icon={<BarChart />} />
            <StatCard title="Blocked by Rate Limit" value={blockedAttempts} icon={<XCircle />} />
            <StatCard title="Logs Saved to DB" value={databaseLogCount} icon={<Database />} />
          </div>
          <ChartCard loginAttempts={loginAttempts} />
        </div>
      </main>
    </div>
  );
};

// --- CHILD COMPONENTS ---

const StatCard = ({ title, value, icon }) => (<div className="bg-gray-800 p-6 rounded-xl shadow-lg"><div className="flex items-center justify-between"><div><p className="text-gray-400">{title}</p><p className="text-4xl font-bold">{value}</p></div><div className="bg-blue-900/50 p-3 rounded-full">{icon}</div></div></div>);
const AttackCard = ({ onAttack, status, results, user }) => (<InfoCard title="Threat Simulation" icon={<AlertTriangle />}><p className="text-sm text-gray-400 mb-4">Simulate a credential stuffing attack against the <span className="font-bold text-yellow-300">{user.username.split('@')[0]}</span> account to test the security systems.</p><button onClick={onAttack} disabled={status === 'running'} className="w-full bg-red-600 hover:bg-red-700 text-white font-bold py-3 px-4 rounded-lg flex items-center justify-center gap-2 transition duration-300 disabled:bg-gray-500 disabled:cursor-not-allowed"><PlayCircle size={20} />{status === 'running' ? 'Attack in Progress...' : 'Start Attack'}</button>{status === 'running' && <div className="mt-4 text-center"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-400 mx-auto"></div><p className="text-sm text-blue-300 mt-2">Sending requests...</p></div>}{status === 'finished' && results && <div className="mt-4 p-4 bg-gray-900 rounded-lg border border-gray-700"><h3 className="font-bold text-center mb-2">Simulation Complete</h3><div className="flex justify-around text-center"><div><p className="text-gray-400 text-sm">Total</p><p className="text-2xl font-bold">{results.total}</p></div><div><p className="text-green-400 text-sm">Successful</p><p className="text-2xl font-bold text-green-400">{results.success}</p></div><div><p className="text-red-400 text-sm">Blocked</p><p className="text-2xl font-bold text-red-400">{results.blocked}</p></div></div></div>}</InfoCard>);

const CompromisedCredentialCard = ({ account }) => (
    <div className="bg-red-900/70 border-2 border-red-500 p-6 rounded-xl shadow-lg">
        <div className="flex items-center gap-4 mb-3">
            <FileWarning className="h-10 w-10 text-yellow-300" />
            <div>
                <h2 className="text-2xl font-bold text-white">Security Alert: Account Compromised!</h2>
                <p className="text-yellow-200 font-semibold">Breached on Attempt: {account.attemptNumber}</p>
            </div>
        </div>
        <div className="bg-gray-900 p-4 rounded-lg font-mono text-sm mb-4">
            <p><span className="font-bold text-gray-400">Username:</span> <span className="text-white">{account.username}</span></p>
            <p><span className="font-bold text-gray-400">Password Hash:</span> <span className="text-white">{account.passwordHash}</span></p>
        </div>
        {account.stolenCart && (
             <div className="bg-gray-900 p-4 rounded-lg">
                <h3 className="text-lg font-bold text-yellow-300 mb-2 flex items-center gap-2"><ShoppingCart size={20}/>Exfiltrated Data: Shopping Cart</h3>
                {account.stolenCart.length > 0 ? (
                    <ul className="list-disc list-inside text-sm text-gray-300">
                        {account.stolenCart.map(item => (
                            <li key={item.id}><span>{item.name}</span> - <span className="font-semibold">${item.price.toFixed(2)}</span></li>
                        ))}
                    </ul>
                ) : (
                    <p className="text-sm text-gray-400">User's shopping cart was empty.</p>
                )}
             </div>
        )}
    </div>
);


const PieChartCard = ({ user }) => {
    const chartRef = useRef(null);
    const chartInstance = useRef(null);

    useEffect(() => {
        if (chartRef.current) {
            if (chartInstance.current) chartInstance.current.destroy();
            const ctx = chartRef.current.getContext('2d');
            const score = user.securityScore;
            const remaining = 100 - score;
            const scoreColor = score > 75 ? 'rgba(74, 222, 128, 1)' : score > 40 ? 'rgba(250, 204, 21, 1)' : 'rgba(248, 113, 113, 1)';
            chartInstance.current = new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: ['Security Score', 'Potential Risk'],
                    datasets: [{ data: [score, remaining], backgroundColor: [scoreColor, 'rgba(255, 255, 255, 0.1)'], borderColor: ['rgba(255,255,255,0.2)', 'rgba(255,255,255,0.1)'], borderWidth: 1 }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#d1d5db' } }, title: { display: true, text: `${user.username.split('@')[0]}'s Security Posture`, color: '#e5e7eb', font: { size: 16 } } } }
            });
        }
        return () => { if (chartInstance.current) chartInstance.current.destroy(); };
    }, [user]);

    return (<InfoCard title="Security Score" icon={<PieChart />}><div className="h-64 w-full relative"><canvas ref={chartRef}></canvas></div></InfoCard>);
};

const ChartCard = ({ loginAttempts }) => {
  const chartRef = useRef(null);
  const chartInstance = useRef(null);

  useEffect(() => {
    if (chartRef.current) {
      if (chartInstance.current) chartInstance.current.destroy();
      const ctx = chartRef.current.getContext('2d');
      const labels = loginAttempts.map((_, index) => index + 1);
      const successData = [], failedData = [];
      let successCount = 0, failedCount = 0;
      loginAttempts.forEach(attempt => {
        if (attempt.status === 'success') successCount++; else failedCount++;
        successData.push(successCount);
        failedData.push(failedCount);
      });
      chartInstance.current = new Chart(ctx, {
        type: 'line',
        data: { labels, datasets: [{ label: 'Successful Logins', data: successData, borderColor: 'rgba(74, 222, 128, 1)', backgroundColor: 'rgba(74, 222, 128, 0.2)', fill: true, tension: 0.3 }, { label: 'Failed Logins', data: failedData, borderColor: 'rgba(248, 113, 113, 1)', backgroundColor: 'rgba(248, 113, 113, 0.2)', fill: true, tension: 0.3 }] },
        options: { responsive: true, maintainAspectRatio: false, scales: { x: { title: { display: true, text: 'Attempt Number', color: '#9ca3af' }, ticks: { color: '#9ca3af' }, grid: { color: 'rgba(255, 255, 255, 0.1)' } }, y: { title: { display: true, text: 'Cumulative Count', color: '#9ca3af' }, ticks: { color: '#9ca3af' }, grid: { color: 'rgba(255, 255, 255, 0.1)' }, beginAtZero: true } }, plugins: { legend: { labels: { color: '#d1d5db' } } } }
      });
    }
    return () => { if (chartInstance.current) chartInstance.current.destroy(); };
  }, [loginAttempts]);

  return (<div className="bg-gray-800 p-6 rounded-xl shadow-lg h-96"><h2 className="text-xl font-semibold mb-4">Login Attempts Over Time</h2><div className="h-full w-full relative"><canvas ref={chartRef}></canvas></div></div>);
};
