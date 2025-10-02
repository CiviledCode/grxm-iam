package token

var RegisteredSources = []TokenSource{
	&JWTSource{},
}
