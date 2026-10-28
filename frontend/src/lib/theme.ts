import { createTheme } from '@mui/material/styles';

const socTheme = createTheme({
  palette: {
    mode: 'light',
    background: {
      default: '#FFF7F8',
      paper: '#FFFFFF',
    },
    primary: {
      main: '#FFB7C5',
      light: '#FFE2E8',
      dark: '#E06D85',
      contrastText: '#2A1822',
    },
    secondary: {
      main: '#F2C7C7',
      light: '#FCECEC',
      dark: '#D89FA1',
      contrastText: '#2A1822',
    },
    success: {
      main: '#2E7D32',
      light: '#D5F3D8',
      contrastText: '#FFFFFF',
    },
    warning: {
      main: '#D97706',
      light: '#FEF3C7',
      contrastText: '#2A1822',
    },
    error: {
      main: '#D8224C',
      light: '#FFE4E8',
      contrastText: '#FFFFFF',
    },
    text: {
      primary: '#2A1822',
      secondary: '#6E5562',
    },
    divider: '#F2C7C7',
  },
  shape: {
    borderRadius: 14,
  },
  typography: {
    fontFamily: '"Inter", sans-serif',
    h1: { fontFamily: '"Space Grotesk", "Inter", sans-serif', color: '#2A1822' },
    h2: { fontFamily: '"Space Grotesk", "Inter", sans-serif', color: '#2A1822' },
    h3: { fontFamily: '"Space Grotesk", "Inter", sans-serif', color: '#2A1822' },
    h4: { fontFamily: '"Space Grotesk", "Inter", sans-serif', color: '#2A1822' },
    h5: { fontFamily: '"Space Grotesk", "Inter", sans-serif', color: '#2A1822' },
    h6: { fontFamily: '"Space Grotesk", "Inter", sans-serif', color: '#2A1822' },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          backgroundColor: '#FFF7F8',
          color: '#2A1822',
        },
      },
    },
  },
});

export const theme = socTheme;
export const darkTheme = socTheme;
export const lightTheme = socTheme;
export default socTheme;
