// Package core holds the types every part of Juggernaut shares and nothing
// else: who is calling (Principal), what they may touch (Grants), the
// identifiers of sessions and pods, and the context adapters are built with.
//
// The layering mirrors cerebro:
//
//	core            value types + AdapterContext           depends on config only
//	core/contracts  one interface per adapter kind         depends on core
//	core/registry   type name -> adapter constructor       depends on contracts
//	adapters/<kind>/<type>  one implementation per package registers itself in init()
//	gateway, controller, router, admin                     depend on contracts, never on adapters
//	app             composition roots (FromConfig)         the only place adapters are chosen
//
// A component that needs a collaborator declares the contract it needs; which
// concrete adapter satisfies it is decided by juggernaut.yaml through the
// registry. Adding an adapter never edits an existing package (open/closed).
package core
