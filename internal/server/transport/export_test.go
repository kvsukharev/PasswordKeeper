package transport

// ContextWithUserID re-exports contextWithUserID so that tests in package
// transport_test can build authenticated contexts without the function being
// part of the public API.
var ContextWithUserID = contextWithUserID
