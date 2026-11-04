// The Boundry portfolio as data (docs/brand.md). Shared marketing components
// read it so every site names the company, links to boundry.company and lists
// its sibling products the same way. Content mirrors rkendel1/boundry
// content/products.json; product accents live in @stack-ui/tokens brand.json.
// A product `href` is its own public site only where that domain was checked
// to serve one (docs/brand.md §7); otherwise it is the product's entry on
// boundry.company.

export const PORTFOLIO = Object.freeze({
  company: Object.freeze({
    name: 'Boundry',
    href: 'https://boundry.company',
    tagline: 'Infrastructure for applications and agents.',
    family: 'Part of the Boundry family of products',
  }),
  products: Object.freeze([
    { id: 'feltdb', name: 'FeltDB', mark: 'FD', category: 'Durable state', href: 'https://feltdb.com' },
    { id: 'feltkit', name: 'FeltKit', mark: 'FK', category: 'Developer platform', href: 'https://getfeltkit.com' },
    { id: 'appboundry', name: 'AppBoundry', mark: 'AB', category: 'Application boundaries', href: 'https://appboundry.com' },
    { id: 'authboundry', name: 'AuthBoundry', mark: 'AU', category: 'Authority and delegation', href: 'https://authboundry.com' },
    { id: 'appport', name: 'AppPort', mark: 'AP', category: 'Application capabilities', href: 'https://boundry.company/ecosystem/#appport' },
  ].map((product) => Object.freeze(product))),
});

/// The portfolio entry for a product id, or null.
export function portfolioProduct(id) {
  return PORTFOLIO.products.find((product) => product.id === id) || null;
}
