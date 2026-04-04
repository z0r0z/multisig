(function() {
'use strict';

const WEINS = '0x0000000000696760E15f265e828DB644A0c242EB';
const WEINS_ABI = ['function reverseResolve(address) view returns (string)'];
const WC_PROJECT_ID = '1e8390ef1c1d8a185e035912a1409749';

const _escMap = { '&': '&amp;', '<': '&lt;', '>': '&gt;' };
function _esc(s) { return String(s).replace(/[&<>]/g, m => _escMap[m]); }

// --- State ---
window._walletProvider = null;
window._signer = null;
window._connectedAddress = null;
window._isWalletConnect = false;
window._connectedWalletProvider = null;
window.eip6963Providers = new Map();

let _walletConnectProvider = null;
let _isConnecting = false;
let _walletEventHandlers = null;
let _onConnectCallbacks = [];
let _onDisconnectCallbacks = [];
let _appName = 'Multisig';
let _targetChainId = 1;
let _targetChainHex = '0x1';
let _targetRpc = 'https://ethereum.publicnode.com';
let _addChainParams = null;

// --- EIP-6963 ---
window.addEventListener('eip6963:announceProvider', (event) => {
  try {
    const { info, provider } = event.detail || {};
    if (info?.uuid && provider) eip6963Providers.set(info.uuid, { info, provider });
  } catch (e) {}
});
window.dispatchEvent(new Event('eip6963:requestProvider'));

// --- Provider detection ---
function detectWallets() {
  const detected = [], seenNames = new Set();
  for (const [uuid, { info, provider }] of eip6963Providers.entries()) {
    const name = info?.name || 'Unknown';
    if (seenNames.has(name.toLowerCase())) continue;
    const iconUrl = info.icon && (info.icon.startsWith('data:image/') || info.icon.startsWith('https://')) ? info.icon : null;
    const safeIcon = iconUrl ? `<img src="${_esc(iconUrl).replace(/"/g, '&quot;').replace(/'/g, '&#39;')}" style="width:1.5rem;height:1.5rem;border-radius:4px;">` : '';
    detected.push({ key: `eip6963_${uuid}`, name, icon: safeIcon, getProvider: () => provider });
    seenNames.add(name.toLowerCase());
  }
  if (!detected.length && window.ethereum) detected.push({ key: 'injected', name: 'Browser Wallet', icon: '', getProvider: () => window.ethereum });
  const wcModule = globalThis['@walletconnect/ethereum-provider'];
  if (wcModule?.EthereumProvider) detected.push({ key: 'walletconnect', name: 'WalletConnect', icon: '' });
  return detected;
}

// --- DOM injection ---
function injectWalletDOM() {
  if (document.getElementById('walletBtn')) return;
  const walletDiv = document.createElement('div');
  walletDiv.className = 'wallet';
  walletDiv.innerHTML = '<button id="walletBtn" onclick="toggleWallet()">connect</button>';
  document.body.appendChild(walletDiv);
  const overlay = document.createElement('div');
  overlay.className = 'wallet-modal-overlay';
  overlay.id = 'walletModal';
  overlay.onclick = function(e) { if (e.target === this) closeWalletModal(); };
  overlay.innerHTML = '<div class="wallet-modal"><div class="wallet-modal-header"><div class="wallet-modal-title">Connect Wallet</div><button class="wallet-modal-close" onclick="closeWalletModal()">&times;</button></div><div class="wallet-modal-body" id="walletOptions"></div></div>';
  document.body.appendChild(overlay);
}

// --- Modal ---
function showWalletModal() {
  document.getElementById('walletModal').classList.add('active');
  document.body.classList.add('modal-open');
  window.dispatchEvent(new Event('eip6963:requestProvider'));
  setTimeout(() => {
    const wallets = detectWallets();
    const container = document.getElementById('walletOptions');
    if (_connectedAddress) {
      const displayName = document.getElementById('walletBtn').textContent;
      container.innerHTML = `<div style="padding:12px;border:1px solid currentColor;margin-bottom:12px;"><div style="font-size:12px;word-break:break-all;opacity:0.6;">${_esc(_connectedAddress)}</div></div><div class="wallet-option disconnect" onclick="disconnectWallet()"><span class="wallet-option-name">Disconnect</span></div>`;
    } else {
      container.innerHTML = wallets.length > 0 ? wallets.map(w => `<div class="wallet-option" data-wallet-key="${_esc(w.key)}">${w.icon ? `<span class="wallet-option-icon">${w.icon}</span>` : ''}<span class="wallet-option-name">${_esc(w.name)}</span></div>`).join('') : '<div style="padding:12px;text-align:center;">No wallets detected.</div>';
      container.querySelectorAll('[data-wallet-key]').forEach(el => { el.addEventListener('click', () => connectWithWallet(el.dataset.walletKey)); });
    }
  }, 200);
}

window.closeWalletModal = function() {
  document.getElementById('walletModal').classList.remove('active');
  document.body.classList.remove('modal-open');
};
window.toggleWallet = function() { showWalletModal(); };
window.showWalletModal = showWalletModal;

// --- Connect ---
async function connectWithWallet(walletKey) {
  if (_isConnecting) return;
  _isConnecting = true;
  try {
    closeWalletModal();
    let walletProvider;
    if (walletKey === 'walletconnect') {
      const wcModule = globalThis['@walletconnect/ethereum-provider'];
      const WCProvider = wcModule?.EthereumProvider;
      if (!WCProvider?.init) throw new Error('WalletConnect not available');
      if (_walletConnectProvider) { try { await _walletConnectProvider.disconnect?.(); } catch (e) {} _walletConnectProvider = null; }
      _walletConnectProvider = await WCProvider.init({ projectId: WC_PROJECT_ID, chains: [_targetChainId], showQrModal: true, rpcMap: { [_targetChainId]: _targetRpc }, metadata: { name: _appName, description: _appName, url: window.location.origin, icons: [] } });
      await _walletConnectProvider.enable();
      walletProvider = _walletConnectProvider;
      _isWalletConnect = true;
    } else if (walletKey.startsWith('eip6963_')) {
      const uuid = walletKey.replace('eip6963_', '');
      walletProvider = eip6963Providers.get(uuid)?.provider;
      if (!walletProvider) {
        const savedName = localStorage.getItem('ms_wallet_name')?.toLowerCase();
        if (savedName) for (const [, { info, provider }] of eip6963Providers) if (info?.name?.toLowerCase() === savedName) { walletProvider = provider; break; }
      }
      _isWalletConnect = false;
    } else {
      walletProvider = window.ethereum;
      _isWalletConnect = false;
    }
    if (!walletProvider) throw new Error('Wallet not found');

    if (walletKey !== 'walletconnect') await walletProvider.request({ method: 'eth_requestAccounts' });

    // Switch to target chain
    const chainId = await walletProvider.request({ method: 'eth_chainId' });
    if (BigInt(chainId) !== BigInt(_targetChainId)) {
      try {
        await walletProvider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: _targetChainHex }] });
      } catch (switchErr) {
        if (switchErr.code === 4902 && _addChainParams) {
          await walletProvider.request({ method: 'wallet_addEthereumChain', params: [_addChainParams] });
        } else throw switchErr;
      }
    }

    _walletProvider = new ethers.BrowserProvider(walletProvider);
    _signer = await _walletProvider.getSigner();
    _connectedAddress = await _signer.getAddress();
    const oldWP = _connectedWalletProvider;
    _connectedWalletProvider = walletProvider;
    document.getElementById('walletBtn').textContent = _connectedAddress.slice(0, 6) + '...' + _connectedAddress.slice(-4);
    document.getElementById('walletBtn').classList.add('connected');

    resolveWeiName(_connectedAddress);

    if (oldWP && _walletEventHandlers) {
      try { oldWP.removeListener('accountsChanged', _walletEventHandlers.accountsChanged); oldWP.removeListener('chainChanged', _walletEventHandlers.chainChanged); } catch (e) {}
    }
    _walletEventHandlers = { accountsChanged: () => window.location.reload(), chainChanged: () => window.location.reload() };
    walletProvider.on('accountsChanged', _walletEventHandlers.accountsChanged);
    walletProvider.on('chainChanged', _walletEventHandlers.chainChanged);

    try { localStorage.setItem('ms_wallet', walletKey); if (walletKey.startsWith('eip6963_')) { const uuid = walletKey.replace('eip6963_', ''); const name = eip6963Providers.get(uuid)?.info?.name; if (name) localStorage.setItem('ms_wallet_name', name); } } catch (e) {}
    for (const fn of _onConnectCallbacks) { try { fn(); } catch (e) { console.error('onConnect error:', e); } }
  } catch (error) {
    console.error('Wallet connect error:', error);
    document.getElementById('walletBtn').textContent = 'connect';
  } finally { _isConnecting = false; }
}

window.disconnectWallet = function() {
  if (_connectedWalletProvider && _walletEventHandlers) { try { _connectedWalletProvider.removeListener('accountsChanged', _walletEventHandlers.accountsChanged); _connectedWalletProvider.removeListener('chainChanged', _walletEventHandlers.chainChanged); } catch (e) {} }
  _walletEventHandlers = null;
  if (_walletConnectProvider) { try { _walletConnectProvider.disconnect(); } catch (e) {} _walletConnectProvider = null; }
  _walletProvider = null; _signer = null; _connectedAddress = null; _connectedWalletProvider = null; _isWalletConnect = false;
  document.getElementById('walletBtn').textContent = 'connect';
  document.getElementById('walletBtn').classList.remove('connected');
  closeWalletModal();
  try { localStorage.removeItem('ms_wallet'); localStorage.removeItem('ms_wallet_name'); } catch (e) {}
  for (const fn of _onDisconnectCallbacks) { try { fn(); } catch (e) {} }
};

window.connectWallet = async function() {
  if (_signer) return _signer;
  showWalletModal();
  return null;
};

const _ethRpcs = [
  'https://ethereum.publicnode.com',
  'https://1rpc.io/eth',
  'https://eth.drpc.org',
];
const _ethMainProvider = new ethers.FallbackProvider(
  _ethRpcs.map((url, i) => ({ provider: new ethers.JsonRpcProvider(url, 1, {staticNetwork:true}), priority: i + 1, stallTimeout: 2000 })), 1
);

function resolveWeiName(addr) {
  try {
    const ns = new ethers.Contract(WEINS, WEINS_ABI, _ethMainProvider);
    ns.reverseResolve(addr).then(name => {
      if (name && _connectedAddress === addr) document.getElementById('walletBtn').textContent = name.toLowerCase();
    }).catch(() => {
      _ethMainProvider.lookupAddress(addr).then(ensName => {
        if (ensName && _connectedAddress === addr) document.getElementById('walletBtn').textContent = ensName;
      }).catch(() => {});
    });
  } catch (e) {}
}
window.resolveWeiName = resolveWeiName;

async function tryAutoConnect() {
  const savedWallet = localStorage.getItem('ms_wallet');
  if (!savedWallet) return;
  document.getElementById('walletBtn').textContent = '...';
  await new Promise(r => setTimeout(r, 400));
  window.dispatchEvent(new Event('eip6963:requestProvider'));
  await new Promise(r => setTimeout(r, 300));
  try {
    let probe;
    if (savedWallet.startsWith('eip6963_')) {
      const uuid = savedWallet.replace('eip6963_', '');
      probe = eip6963Providers.get(uuid)?.provider;
      if (!probe) { const savedName = localStorage.getItem('ms_wallet_name')?.toLowerCase(); if (savedName) for (const [, { info, provider }] of eip6963Providers) if (info?.name?.toLowerCase() === savedName) { probe = provider; break; } }
    } else if (savedWallet !== 'walletconnect') probe = window.ethereum;
    if (probe) { const accts = await probe.request({ method: 'eth_accounts' }); if (!accts || accts.length === 0) { document.getElementById('walletBtn').textContent = 'connect'; return; } }
    await connectWithWallet(savedWallet);
  } catch (e) {
    document.getElementById('walletBtn').textContent = 'connect';
  }
}

// --- Public API ---
window.walletInit = function(opts) {
  _appName = opts.appName || 'Multisig';
  _targetChainId = opts.chainId || 1;
  _targetChainHex = opts.chainHex || '0x' + _targetChainId.toString(16);
  _targetRpc = opts.rpc || 'https://ethereum.publicnode.com';
  _addChainParams = opts.addChainParams || null;
  _onConnectCallbacks = Array.isArray(opts.onConnect) ? opts.onConnect : (opts.onConnect ? [opts.onConnect] : []);
  _onDisconnectCallbacks = Array.isArray(opts.onDisconnect) ? opts.onDisconnect : (opts.onDisconnect ? [opts.onDisconnect] : []);
  injectWalletDOM();
  tryAutoConnect();
};

// Switch chain at runtime (called when user switches network)
window.walletSwitchChain = async function(opts) {
  _targetChainId = opts.chainId;
  _targetChainHex = opts.chainHex || '0x' + opts.chainId.toString(16);
  _targetRpc = opts.rpc || _targetRpc;
  _addChainParams = opts.addChainParams || null;
  if(_connectedWalletProvider) {
    try {
      const current = await _connectedWalletProvider.request({method:'eth_chainId'});
      if(BigInt(current) !== BigInt(_targetChainId)) {
        try { await _connectedWalletProvider.request({method:'wallet_switchEthereumChain', params:[{chainId:_targetChainHex}]}); }
        catch(e) { if(e.code===4902 && _addChainParams) await _connectedWalletProvider.request({method:'wallet_addEthereumChain', params:[_addChainParams]}); }
      }
    } catch(_) {}
  }
};

})();
