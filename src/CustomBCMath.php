<?php

namespace Enrico\CognitoAws;

class CustomBCMath
{
    public static function customBcPowMod($x, $y, $modulus)
    {
        $t = '1';
        while (bccomp($y, '0')) {
            if (bccomp(self::customBcMod($y, '2'), '0')) {
                $t = self::customBcMod(bcmul($t, $x), $modulus);
                $y = bcsub($y, '1');
            }

            $x = self::customBcMod(bcmul($x, $x), $modulus);
            $y = bcdiv($y, '2');
        }

        return $t;
    }

    public static function customBcMod($number, $modulus)
    {
        return bcmod(bcadd($modulus, bcmod($number, $modulus)), $modulus);
    }
}