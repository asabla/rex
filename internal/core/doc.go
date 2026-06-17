// Package core holds logic shared across Rex surfaces. In this repo it
// backs the local node (cmd/rex); the standalone central server mirrors
// the relevant packages in the separate rex-lab repository.
//
// No core package may branch on whether it is running on a local or
// central node.
//
// Subpackages add capability vertically (event envelope, storage, sync,
// execution, ...). Each subpackage owns its sync category per
// overview.SYS.2 and is the source of truth for the contract its callers
// rely on.
package core
