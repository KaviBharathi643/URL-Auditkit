import { createTheme } from '@mui/material/styles';

const socTheme = createTheme({
  palette: {
    mode: 'dark',
    background: {
      default: '#0b0f17',
      paper: '#111827',
    },
    primary: {
      main: '#06b6d4',
    },
    secondary: {
      main: '#3b82f6',
    },
    success: {
      main: '#10b981',
    },
    warning: {
      main: '#f59e0b',
    },
    error: {
      main: '#ef4444',
    },
    text: {
      primary: '#e5eefb',
      secondary: '#94a3b8',
    },
    divider: '#1f2937',
  },
  shape: {
    borderRadius: 12,
  },
  typography: {
    fontFamily: '"Inter", sans-serif',
    h1: { fontFamily: '"Space Grotesk", "Inter", sans-serif' },
    h2: { fontFamily: '"Space Grotesk", "Inter", sans-serif' },
    h3: { fontFamily: '"Space Grotesk", "Inter", sans-serif' },
    h4: { fontFamily: '"Space Grotesk", "Inter", sans-serif' },
    h5: { fontFamily: '"Space Grotesk", "Inter", sans-serif' },
    h6: { fontFamily: '"Space Grotesk", "Inter", sans-serif' },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundColor: '#0b0f17',
        },
      },
    },
  },
});

export const theme = socTheme;
export const darkTheme = socTheme;
export const lightTheme = socTheme;
export default socTheme;
