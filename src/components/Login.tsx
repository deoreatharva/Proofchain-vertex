import React, { useState, useId, useRef, KeyboardEvent } from 'react';

/**
 * ProofChain Authentication Types
 */
export type RoleType = 'holder' | 'issuer' | 'verifier';

export interface LoginFormData {
  role: RoleType;
  identifier: string;
  password?: string;
  rememberDevice: boolean;
}

export interface RoleConfig {
  id: RoleType;
  label: string;
  subtitle: string;
  headerTitle: string;
  description: string;
  targetRoute: string;
  identifierLabel: string;
  identifierPlaceholder: string;
  isPasswordRequired: boolean;
  showPasswordField: boolean;
  allowStatelessBypass: boolean;
}

export interface LoginProps {
  initialRole?: RoleType;
  onSubmit?: (data: LoginFormData, targetRoute: string) => void | Promise<void>;
  onNavigate?: (route: string) => void;
  onForgotPassword?: (role: RoleType) => void;
}

const ROLE_CONFIGS: Record<RoleType, RoleConfig> = {
  holder: {
    id: 'holder',
    label: 'Holder',
    subtitle: 'Normal User / Record Holder',
    headerTitle: 'Record Holder Login',
    description: 'Access your sovereign attested credentials and cryptographically verified documents.',
    targetRoute: '/my-records',
    identifierLabel: 'Email or Account ID',
    identifierPlaceholder: 'holder@domain.com or ID-88214',
    isPasswordRequired: true,
    showPasswordField: true,
    allowStatelessBypass: false,
  },
  issuer: {
    id: 'issuer',
    label: 'Issuer',
    subtitle: 'Registry Operator / Authority',
    headerTitle: 'Registry Authority Login',
    description: 'Authenticate with administrative credentials to ingest, canonicalize, and anchor batches.',
    targetRoute: '/register',
    identifierLabel: 'Operator ID / Service Email',
    identifierPlaceholder: 'op_gov_registrar or operator@proofchain.network',
    isPasswordRequired: true,
    showPasswordField: true,
    allowStatelessBypass: false,
  },
  verifier: {
    id: 'verifier',
    label: 'Verifier',
    subtitle: 'Recruiter / Auditor',
    headerTitle: 'Verifier Portal',
    description: 'Verify cryptographic Merkle proofs and Ed25519 signatures independently via WebCrypto.',
    targetRoute: '/verify',
    identifierLabel: 'Auditor Email (Optional)',
    identifierPlaceholder: 'auditor@firm.org (optional for audit trail)',
    isPasswordRequired: false,
    showPasswordField: false,
    allowStatelessBypass: true,
  },
};

/**
 * ProofChain Production-Ready Accessible React Login Component
 * Strictly adheres to monochrome grayscale guidelines (no colors, no gradients, sharp/2px borders).
 */
export const Login: React.FC<LoginProps> = ({
  initialRole = 'holder',
  onSubmit,
  onNavigate,
  onForgotPassword,
}) => {
  const [activeRole, setActiveRole] = useState<RoleType>(initialRole);
  const [identifier, setIdentifier] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [rememberDevice, setRememberDevice] = useState<boolean>(false);
  const [showPassword, setShowPassword] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const identifierId = useId();
  const passwordId = useId();
  const rememberId = useId();

  const tabRefs = useRef<Record<RoleType, HTMLButtonElement | null>>({
    holder: null,
    issuer: null,
    verifier: null,
  });

  const currentConfig = ROLE_CONFIGS[activeRole];

  const handleRoleChange = (role: RoleType) => {
    setActiveRole(role);
    setErrorMessage(null);
  };

  const handleKeyDownTab = (e: KeyboardEvent<HTMLButtonElement>, role: RoleType) => {
    const roles: RoleType[] = ['holder', 'issuer', 'verifier'];
    const currentIndex = roles.indexOf(role);

    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
      e.preventDefault();
      const nextRole = roles[(currentIndex + 1) % roles.length];
      handleRoleChange(nextRole);
      tabRefs.current[nextRole]?.focus();
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      e.preventDefault();
      const prevRole = roles[(currentIndex - 1 + roles.length) % roles.length];
      handleRoleChange(prevRole);
      tabRefs.current[prevRole]?.focus();
    }
  };

  const handleFormSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setErrorMessage(null);

    // Validation
    if (currentConfig.id !== 'verifier' && !identifier.trim()) {
      setErrorMessage(`${currentConfig.identifierLabel} is required.`);
      return;
    }

    if (currentConfig.isPasswordRequired && !password) {
      setErrorMessage('Passphrase or security key is required.');
      return;
    }

    const payload: LoginFormData = {
      role: activeRole,
      identifier: identifier.trim(),
      password: currentConfig.showPasswordField ? password : undefined,
      rememberDevice,
    };

    setIsSubmitting(true);
    try {
      if (onSubmit) {
        await onSubmit(payload, currentConfig.targetRoute);
      } else if (onNavigate) {
        onNavigate(currentConfig.targetRoute);
      } else {
        // Fallback default browser redirection
        window.location.href = currentConfig.targetRoute;
      }
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Authentication failed. Please verify credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleBypassClick = () => {
    if (onNavigate) {
      onNavigate(currentConfig.targetRoute);
    } else {
      window.location.href = currentConfig.targetRoute;
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#FFFFFF] text-[#000000] flex flex-col justify-center items-center p-4 sm:p-6 font-sans antialiased">
      <main className="w-full max-w-[440px] border border-black bg-white rounded-[2px] p-0 flex flex-col">
        {/* Top Minimal Branding Header */}
        <header className="border-b border-black p-4 sm:p-5 flex items-center justify-between bg-[#F4F4F5]">
          <div>
            <span className="font-mono text-sm tracking-widest font-bold block uppercase text-black">
              PROOFCHAIN
            </span>
            <span className="font-mono text-[10px] text-[#71717A] tracking-wider block uppercase mt-0.5">
              Protocol Gateway // v1.0
            </span>
          </div>
          <div className="border border-black px-2 py-0.5 font-mono text-[11px] uppercase bg-white">
            SECURE_AUTH
          </div>
        </header>

        {/* 1. 3-Way Tabbed Role Selector */}
        <nav
          role="tablist"
          aria-label="Access Role Selector"
          className="grid grid-cols-3 border-b border-black bg-[#F4F4F5]"
        >
          {(['holder', 'issuer', 'verifier'] as RoleType[]).map((roleKey) => {
            const roleItem = ROLE_CONFIGS[roleKey];
            const isActive = activeRole === roleKey;

            return (
              <button
                key={roleKey}
                ref={(el) => (tabRefs.current[roleKey] = el)}
                type="button"
                role="tab"
                id={`tab-${roleKey}`}
                aria-selected={isActive}
                aria-controls={`panel-${roleKey}`}
                tabIndex={isActive ? 0 : -1}
                onClick={() => handleRoleChange(roleKey)}
                onKeyDown={(e) => handleKeyDownTab(e, roleKey)}
                className={`py-3 px-2 text-center transition-colors focus:outline-none focus:ring-1 focus:ring-black ${
                  isActive
                    ? 'bg-black text-white font-mono font-bold'
                    : 'bg-[#F4F4F5] text-black hover:bg-[#E4E4E7] font-mono'
                }`}
              >
                <span className="block text-xs uppercase tracking-wider">{roleItem.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Tab Panel & Content */}
        <div
          role="tabpanel"
          id={`panel-${activeRole}`}
          aria-labelledby={`tab-${activeRole}`}
          className="p-5 sm:p-6 flex flex-col flex-1"
        >
          {/* Dynamic Role Description */}
          <div className="mb-6 pb-4 border-b border-[#E4E4E7]">
            <div className="flex items-center justify-between gap-2 mb-1.5">
              <h1 className="font-sans text-base font-bold tracking-tight text-black">
                {currentConfig.headerTitle}
              </h1>
              <span className="font-mono text-[11px] text-[#71717A] uppercase">
                &rarr; {currentConfig.targetRoute}
              </span>
            </div>
            <p className="text-xs text-[#71717A] leading-relaxed">
              {currentConfig.description}
            </p>
          </div>

          {/* Form Error Alert */}
          {errorMessage && (
            <div
              role="alert"
              aria-live="assertive"
              className="mb-5 p-3 border border-black bg-[#F4F4F5] text-xs font-mono text-black"
            >
              <span className="font-bold mr-1.5">[ERROR]:</span>
              {errorMessage}
            </div>
          )}

          {/* Login Form */}
          <form onSubmit={handleFormSubmit} noValidate className="space-y-4 flex-1">
            {/* Dynamic Identifier Field */}
            <div className="space-y-1.5">
              <label
                htmlFor={identifierId}
                className="block font-mono text-xs font-medium uppercase tracking-wide text-black"
              >
                {currentConfig.identifierLabel}
              </label>
              <input
                id={identifierId}
                type="text"
                autoComplete="username"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                placeholder={currentConfig.identifierPlaceholder}
                disabled={isSubmitting}
                className="w-full px-3 py-2 text-xs font-mono text-black bg-white border border-black rounded-[2px] placeholder-[#71717A] focus:outline-none focus:ring-1 focus:ring-black disabled:opacity-50"
              />
            </div>

            {/* Password Field (Dynamic visibility per role) */}
            {currentConfig.showPasswordField && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor={passwordId}
                    className="block font-mono text-xs font-medium uppercase tracking-wide text-black"
                  >
                    Passphrase / Access Key
                  </label>
                  {onForgotPassword && (
                    <button
                      type="button"
                      onClick={() => onForgotPassword(activeRole)}
                      className="font-mono text-[11px] text-[#71717A] hover:text-black underline underline-offset-2"
                    >
                      Reset
                    </button>
                  )}
                </div>
                <div className="relative">
                  <input
                    id={passwordId}
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter security passphrase"
                    disabled={isSubmitting}
                    className="w-full px-3 py-2 pr-14 text-xs font-mono text-black bg-white border border-black rounded-[2px] placeholder-[#71717A] focus:outline-none focus:ring-1 focus:ring-black disabled:opacity-50"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? 'Hide passphrase' : 'Show passphrase'}
                    className="absolute right-2 top-1/2 -translate-y-1/2 px-1.5 py-0.5 text-[10px] font-mono text-[#71717A] hover:text-black border border-[#D4D4D8] bg-[#F4F4F5]"
                  >
                    {showPassword ? 'HIDE' : 'SHOW'}
                  </button>
                </div>
              </div>
            )}

            {/* Remember Session Checkbox */}
            <div className="flex items-center gap-2 pt-1">
              <input
                id={rememberId}
                type="checkbox"
                checked={rememberDevice}
                onChange={(e) => setRememberDevice(e.target.checked)}
                disabled={isSubmitting}
                className="h-3.5 w-3.5 rounded-none border border-black text-black accent-black focus:ring-0 focus:outline-none"
              />
              <label htmlFor={rememberId} className="font-mono text-[11px] text-[#71717A] select-none">
                Remember session on this client
              </label>
            </div>

            {/* Submit Button */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-2.5 px-4 font-mono text-xs font-bold uppercase tracking-wider bg-black text-white border border-black rounded-[2px] hover:bg-neutral-800 focus:outline-none focus:ring-1 focus:ring-black transition-colors disabled:opacity-50"
              >
                {isSubmitting
                  ? 'Authenticating...'
                  : activeRole === 'verifier'
                  ? 'Enter Auditor Session'
                  : 'Authenticate & Proceed'}
              </button>
            </div>
          </form>

          {/* Secondary Bypass Option for Verifiers */}
          {currentConfig.allowStatelessBypass && (
            <div className="mt-4 pt-4 border-t border-[#E4E4E7] text-center">
              <button
                type="button"
                onClick={handleBypassClick}
                className="w-full py-2 px-3 font-mono text-xs text-black border border-black bg-white hover:bg-[#F4F4F5] rounded-[2px] transition-colors focus:outline-none focus:ring-1 focus:ring-black block"
              >
                Proceed to Stateless Verifier (No Login Required) &rarr;
              </button>
              <p className="font-mono text-[10px] text-[#71717A] mt-2">
                Pure WebCrypto verification operates locally without network or account credentials.
              </p>
            </div>
          )}
        </div>

        {/* Minimal Footer */}
        <footer className="border-t border-black p-3 bg-[#F4F4F5] text-center">
          <span className="font-mono text-[10px] text-[#71717A] uppercase tracking-wider">
            Zero-Knowledge Merkle Registry // RFC 8785 // Ed25519
          </span>
        </footer>
      </main>
    </div>
  );
};

export default Login;
