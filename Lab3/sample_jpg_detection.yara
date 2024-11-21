rule jpg
{
    meta:
        description = "Identifies if a file is a .jpg"
    strings:
        $s1 = {xx xx}
    condition:
        $s1 at 0 

}