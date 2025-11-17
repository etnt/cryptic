# ALIAS - a poor mans chat room

Until proper chat rooms has been implemented `alias` make it possible
to define an alias for a number of users and then refer to the alias
to send the same message to all the members of the alias.


## Features

The necessary Shell commands that are needed (short form in parenthesis):

- alias (:a) - main command , defaults to: `alias list`
- alias list (:al) - list the existing aliases, example of output:
    @work : alice bob dave
    @gym  : bob dave
- alias new <alias-name> <members> (:an) - create a new alias
- alias delete <alias-name> (:ad) - delete an alias
- alias add <alias-name> <members> (:aa) - add members to an existing alias
- alias rm <alias-name> <members> (:ar) - remove members from an existing alias

The send a message to an alias we add an at sign (@) in front of the alias name.
Example:

  send @work Coffee break!?

This will cause the message to be sent to all members in the alias, hence
it is equivalent to:

  send alice Coffee break!?
  send bob Coffee break!?
  send dave Coffee break!?


## Implementation

The alias functionality should be implemented in a separate Erlang module:
`cryptic_alias.erl`.

The exported function API should contain:

- intialize() - create an ETS table hold the aliases
- new(Alias, ListOfMembers) - store a new alias with given members
- delete(Alias) - delete the given alias
- add(Alias, ListOfMembers) - add given members to an existing alias
- rm(Alias, ListOfMembers) - remove given members from an existing alias
- list(Alias) - return the list of members for a given alias

