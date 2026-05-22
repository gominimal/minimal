let {Target, ..} = import "minimal.ncl" in
{
    target | Target | doc "The system that the software is being compiled for." = __minimal_injected_config.target,

    param | String -> Dyn | doc "Reads the named parameter passed into the layer." =
      fun name => __minimal_injected_config.args."%{name}",
}
