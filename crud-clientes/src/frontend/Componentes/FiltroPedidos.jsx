// FiltroPedidos.jsx
import React from 'react';
import { Modal } from 'react-bootstrap';
import { FaCheck } from 'react-icons/fa';
import './StylesComponent.css';

const FiltroPedidos = ({ show, handleClose, handleSort, selectedOption }) => {
  return (
    <Modal show={show} onHide={handleClose} centered>
      <Modal.Header closeButton className="filtro-modal-header">
        <Modal.Title>Organizar Por:</Modal.Title>
      </Modal.Header>
      <Modal.Body className="filtro-modal-body">
        <button
          className={`filtro-opcion ${selectedOption === 'fechaDesc' ? 'selected' : ''}`}
          onClick={() => handleSort('fechaDesc')}
        >
          <span className="filtro-texto">Fecha del pedido (más reciente a más antiguo)</span>
          {selectedOption === 'fechaDesc' && <FaCheck className="check-icon" />}
        </button>
        <button
          className={`filtro-opcion ${selectedOption === 'fechaAsc' ? 'selected' : ''}`}
          onClick={() => handleSort('fechaAsc')}
        >
          <span className="filtro-texto">Fecha del pedido (más antiguo a más reciente)</span>
          {selectedOption === 'fechaAsc' && <FaCheck className="check-icon" />}
        </button>
        <button
          className={`filtro-opcion ${selectedOption === 'precioAsc' ? 'selected' : ''}`}
          onClick={() => handleSort('precioAsc')}
        >
          <span className="filtro-texto">Precio (menor a mayor)</span>
          {selectedOption === 'precioAsc' && <FaCheck className="check-icon" />}
        </button>
        <button
          className={`filtro-opcion ${selectedOption === 'precioDesc' ? 'selected' : ''}`}
          onClick={() => handleSort('precioDesc')}
        >
          <span className="filtro-texto">Precio (mayor a menor)</span>
          {selectedOption === 'precioDesc' && <FaCheck className="check-icon" />}
        </button>
        <button
          className={`filtro-opcion ${selectedOption === 'sinVer' ? 'selected' : ''}`}
          onClick={() => handleSort('sinVer')}
        >
          <span className="filtro-texto">Pedidos sin ver</span>
          {selectedOption === 'sinVer' && <FaCheck className="check-icon" />}
        </button>
        <button
          className={`filtro-opcion ${selectedOption === 'enProceso' ? 'selected' : ''}`}
          onClick={() => handleSort('enProceso')}
        >
          <span className="filtro-texto">Pedidos en proceso</span>
          {selectedOption === 'enProceso' && <FaCheck className="check-icon" />}
        </button>
        <button
          className={`filtro-opcion ${selectedOption === 'entregados' ? 'selected' : ''}`}
          onClick={() => handleSort('entregados')}
        >
          <span className="filtro-texto">Pedidos entregados</span>
          {selectedOption === 'entregados' && <FaCheck className="check-icon" />}
        </button>
      </Modal.Body>
    </Modal>
  );
};

export default FiltroPedidos;
