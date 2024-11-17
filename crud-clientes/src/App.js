import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Inicio from './frontend/Paginas/Inicio';
import Perfil from './frontend/Paginas/Perfil';
import Productos from './frontend/Paginas/Productos';
import DetalleProducto from './frontend/Paginas/DetalleProducto';
import PaginaCarrito from './frontend/Paginas/PaginaCarrito';
import PaginaFavoritos from './frontend/Paginas/PaginaFavoritos';
import Pedidos from './frontend/Paginas/Pedidos';
import Registro from './frontend/Login/Registro';
import RegisterForm from './frontend/Login/RegisterForm';
import PrivateRoute from './frontend/Login/PrivateRoute';

const App = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Registro />} />
        <Route path="/register" element={<RegisterForm />} />
        <Route path="/" element={<PrivateRoute><Inicio /></PrivateRoute>} />
        <Route path="/Inicio" element={<PrivateRoute><Inicio /></PrivateRoute>} />
        <Route path="/Perfil" element={<PrivateRoute><Perfil /></PrivateRoute>} />
        <Route path="/Productos" element={<PrivateRoute><Productos /></PrivateRoute>} />
        <Route path="/DetalleProducto/:id" element={<PrivateRoute><DetalleProducto /></PrivateRoute>} />
        <Route path="/Carrito" element={<PrivateRoute><PaginaCarrito /></PrivateRoute>} />
        <Route path="/Favoritos" element={<PrivateRoute><PaginaFavoritos /></PrivateRoute>} />
        <Route path="/Pedidos" element={<PrivateRoute><Pedidos /></PrivateRoute>} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;