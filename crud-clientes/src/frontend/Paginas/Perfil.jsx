import './StylesPaginas.css';  
import Navbar from '../Componentes/Navbar';
import PerfilUsuario from '../Componentes/PerfilUsuario'; // Importar el nuevo componente

function Perfil() {
  return (
    <>
      <Navbar />
      <h2></h2>
      <PerfilUsuario /> {/* Incluimos el componente de perfil de usuario */}
    </>
  );
}

export default Perfil;