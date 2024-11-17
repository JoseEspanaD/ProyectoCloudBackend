import React from 'react';
import Navbar from '../Componentes/Navbar';
import ListaFavoritos from '../Componentes/ListaFavoritos';
import './StylesPaginas.css';

const PaginaFavoritos = () => {
  return (
    <>
      <Navbar />
      <ListaFavoritos />
    </>
  );
};

export default PaginaFavoritos;