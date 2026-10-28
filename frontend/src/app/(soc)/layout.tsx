import type { ReactNode } from 'react';
import SOCShell from '@/components/layout/SOCShell';

export default function SOCGroupLayout({ children }: { children: ReactNode }) {
  return <SOCShell>{children}</SOCShell>;
}
