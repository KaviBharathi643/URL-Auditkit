'use client';

import { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { usePathname } from 'next/navigation';
import TopBar from './TopBar';
import Sidebar from './Sidebar';
import RightRail from './RightRail';

interface SOCShellProps {
  children: React.ReactNode;
}

export default function SOCShell({ children }: SOCShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const pathname = usePathname();

  return (
    <div className="soc-shell">
      <TopBar onMenuToggle={() => setSidebarOpen((value) => !value)} />
      <div className="soc-body">
        <AnimatePresence>
          {sidebarOpen && (
            <motion.button
              className="sidebar-overlay"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSidebarOpen(false)}
              aria-label="Close navigation"
            />
          )}
        </AnimatePresence>

        <Sidebar open={sidebarOpen} onNavigate={() => setSidebarOpen(false)} />

        <main className="soc-main" id="main-content">
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25, ease: 'easeOut' }}
          >
            {children}
          </motion.div>
        </main>

        <RightRail />
      </div>
    </div>
  );
}
