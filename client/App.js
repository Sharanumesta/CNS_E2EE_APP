import 'react-native-get-random-values'; // first import in App.js

import { Provider as PaperProvider, DefaultTheme } from 'react-native-paper';
import { createAppContainer } from 'react-navigation';
import { createStackNavigator } from 'react-navigation-stack';

import LoginScreen from './src/screens/LoginScreen';
import RegisterScreen from './src/screens/RegisterScreen';
import StudentScreen from './src/screens/StudentScreen.js';
import MessageScreen from './src/screens/MessageScreen';
import FacultyScreen from './src/screens/FacultyScreen.js';

const AppNavigator = createStackNavigator(
  {
    Login: { screen: LoginScreen },
    Register: { screen: RegisterScreen },
    Dashboard: { screen: StudentScreen },
    Message: { screen: MessageScreen },
    FacultyScreen: { screen: FacultyScreen },
    StudentScreen: { screen: StudentScreen },
  },
  {
    initialRouteName: 'Login',
    // initialRouteName: 'FacultySendMessage',
    defaultNavigationOptions: {
      headerStyle: {
        backgroundColor: '#1E90FF',
      },
      headerTintColor: '#FFFFFF',
      headerTitleStyle: {
        fontWeight: 'bold',
      },
    },
  }
);

const AppContainer = createAppContainer(AppNavigator);

const theme = {
  ...DefaultTheme,
  colors: {
    ...DefaultTheme.colors,
    primary: '#1E90FF', // your primary color
    accent: '#03dac4',
  },
};

export default function App() {
  return (
    <PaperProvider theme={theme}>
      <AppContainer />
    </PaperProvider>
  );
}
