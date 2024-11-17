import React from 'react';
import './StylesPaginas.css';  
import Navbar from '../Componentes/Navbar';
import HistorialPedidos from '../Componentes/HistorialPedidos';

function Pedidos() {
  return (
    <>
      <Navbar />
      <HistorialPedidos />
    </>
  );
}

export default Pedidos;