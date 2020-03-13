rule SecondRule
{
 
    strings:
        $my_text_string = "You have won the lottery" nocase
        $other_text = "Trust me" nocase
        $text = "Give me your ssn" nocase


    condition:
        any of them 
}