import axios from 'axios';

const API = axios.create({
  baseURL: process.env.NODE_ENV === 'production'
    ? process.env.REACT_APP_API_URL || '/api'
    : 'http://localhost:5000/api',
  headers: {
    'Content-Type': 'application/json',
  }
});

// Add auth token to requests
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default API;
