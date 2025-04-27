import API from './api';

export const signup = async (userData) => {
  try {
    const response = await API.post('/signup', userData);
    return response.data;
  } catch (error) {
    throw error.response?.data || error;
  }
};

export const login = async (credentials) => {
  try {
    const response = await API.post('/login', credentials);
    return response.data;
  } catch (error) {
    throw new Error(
      error.response?.data?.message || 'Login failed. Please try again.'
    );
  }
};

export const logout = async () => {
  try {
    const response = await API.post('/logout');
    return response.data;
  } catch (error) {
    console.error('Logout error:', error);
    throw error;
  }
};
