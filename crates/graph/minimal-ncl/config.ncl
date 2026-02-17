let ic = import "__injected_config__.ncl" in
let {Target, ..} = import "minimal.ncl" in
{
    target | Target | doc "The system that the software is being compiled for." = ic.target,
}
