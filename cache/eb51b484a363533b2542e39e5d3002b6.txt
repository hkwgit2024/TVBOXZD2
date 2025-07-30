import { Plano, ServicoAdicional } from '../tipos/planos';

const recursosComuns = [
  {
    titulo: 'Canais em Alta Definição',
    descricao: 'Canais FHD, HD e SD com qualidade superior',
    icone: 'Tv'
  },
  {
    titulo: 'Eventos Pay-per-view',
    descricao: 'Canais Perperview de Esportes e Reality Shows',
    icone: 'Star'
  },
  {
    titulo: 'Canais 24 Horas',
    descricao: 'Canais personalizados de desenhos, séries e filmes',
    icone: 'Clock'
  },
  {
    titulo: 'Monitoramento Avançado',
    descricao: 'Painel para gerenciar conexões ativas',
    icone: 'Activity'
  },
  {
    titulo: 'Suporte Premium',
    descricao: 'Suporte prioritário e avisos importantes',
    icone: 'HeadSet'
  },
  {
    titulo: 'Biblioteca de Conteúdo',
    descricao: 'Mais de 250.000 títulos entre filmes e séries',
    icone: 'Film'
  }
];

export const planos: Plano[] = [
  {
    id: 1,
    nome: 'Plano 50 Conexões',
    preco: 500.00,
    conexoes: 50,
    recursos: [
      {
        titulo: 'Conexões Simultâneas',
        descricao: '50 conexões + 10 de brinde',
        icone: 'Users'
      },
      ...recursosComuns
    ]
  },
  {
    id: 2,
    nome: 'Plano Personalizado',
    preco: 0,
    conexoes: 'personalizado',
    recursos: [
      {
        titulo: 'Conexões Flexíveis',
        descricao: 'Escolha a quantidade ideal + 10-15% de brinde',
        icone: 'Settings'
      },
      ...recursosComuns
    ],
    destaque: true,
    precoBase: 4,
  },
  {
    id: 3,
    nome: 'Plano Full',
    preco: 4000.00,
    conexoes: 'ilimitado',
    recursos: [
      {
        titulo: 'Conexões Enterprise',
        descricao: 'Conexões ilimitadas para seu negócio',
        icone: 'Building'
      },
      ...recursosComuns,
      {
        titulo: 'Suporte VIP',
        descricao: 'Prioridade máxima no atendimento',
        icone: 'Crown'
      }
    ]
  }
];

export const servicosAdicionais: ServicoAdicional[] = [
  {
    id: 1,
    nome: 'Instalação Xtream UI e Xui.One',
    descricao: 'Instalação e configuração completa do Xtream UI ou Xui.One em seu servidor, com otimizações de performance',
    preco: 149.90,
    icone: 'Settings',
    tipo: 'unico'
  },
  {
    id: 2,
    nome: 'Configurações Gerais',
    descricao: 'Configuração otimizada de servidor Linux, firewall, segurança e performance para IPTV',
    preco: 199.90,
    icone: 'Server',
    tipo: 'unico'
  },
  {
    id: 4,
    nome: 'Painel Office',
    descricao: 'Painel administrativo completo para revendedores com gestão de clientes e financeiro',
    preco: 299.90,
    icone: 'LayoutDashboard',
    tipo: 'mensal'
  },
  {
    id: 5,
    nome: 'Script de Upload em Massa',
    descricao: 'Ferramenta automatizada para upload de filmes, séries e canais em lote com organização automática',
    preco: 179.90,
    icone: 'Upload',
    tipo: 'unico'
  }
];