<?php
$dfmode = PASSWORD_DEFAULT;
$imgdir = './avatars/';

trait SQL {
    public function __toWrite(array $data, $dbname, ...$othr) {
        $query = "INSERT INTO $dbname (".implode(", ", array_keys($data)).") 
                  VALUES (".implode(", ", array_fill(0, count($data), "?")).")";
        $resarr = [];
        foreach ($data as $v) {
            $resarr[] = $this->pdo->quote($v);
        }
        $res = $this->pdo->prepare($query);
        $res = $res->execute($resarr);
        return $res;
    }
    public function __toUpdate(array $data, $dbname, array $othr) {
        $arrdata = [];
        $arrothr = [];
        foreach ($data as $k => $v) {
            $arrdata[] = $k." = ".$this->pdo->quote($v);
        }
        foreach ($othr as $k => $v) {
            $arrothr[] = $k." = "."\"".$this->pdo->quote($v)."\"";
        }
        $query = "UPDATE $dbname SET ".implode(', ', $arrdata)." WHERE ".implode(', ', $arrothr);
        return $this->pdo->exec($query);
    }
    public function __toSelect($data, $dbname, $othr = '', $mode = PDO::FETCH_ASSOC) {
        $data = gettype($data) === 'string' ? $data : implode(', ', $data);
        $query = "SELECT ".
            $data
            ." FROM $dbname ".$othr;
        return $this->pdo->query($query)->fetchAll($mode);
    }
}


class Authorization {
    use SQL;
    
    protected $pdo;
    public function __construct(array $dbdata) {
        $dbdata[] = [PDO::ATTR_ERRMODE => PDO::ERRMODE_WARNING];
        $this->pdo = new PDO(...$dbdata);
    }
    public static function validating($data, $fltrs = FILTER_VALIDATE_EMAIL, $empty = true) {
        if (gettype($data) === 'string') return (bool)filter_var($data, $fltrs);
        else {
            if(gettype($fltrs) === 'array' and !empty($fltrs)) {
                $res = filter_var_array($data, $fltrs, $empty);
                foreach ($res as $v) {
                    if ($v === false) return false;
                }
                return true;
            }
            $cfltrs = [];
            foreach ($data as $k => $v) {
                $cfltrs[$k] = $fltrs;
            }
            $res = filter_var_array($data, $cfltrs, $empty);
            foreach ($res as $v) {
                if ($v === false) return false;
            }
            return true;
        }
    }
    public static function sendEmail($email) {
        if (!self::validating($email)) throw new Exception('Invalid email');
        $code = random_int(1000, 9999);
        if(mail($email, 'Sequel Code', "Hey, here is your verification code: $code")) return $code;
        else throw new Exception('Failed to send');
    }
}

class LogIn extends Authorization {
    public function __construct(array $data, array $dbdata, $code = false) {
        if ($code !== false and @$data['code'] != $code) throw new Exception('Invalid code');
        unset($data['code']);
        parent::__construct($dbdata);
        $this->data = $data;
    }
    public function dataChecking($dbname, $cookieaccess = true) {
        $data = $this->__toSelect(['login', 'pass'], $dbname);
        foreach ($data as $v) {
            if (isset($_COOKIE['datareg']) && $cookieaccess){
                $datareg = @unserialize($_COOKIE['datareg']);
                if ($this->pdo->quote($datareg['login']) === $v['login']) {
                    $respass = $datareg['pass'] === substr($v['pass'], 1, -1);
                    if (!$respass) {
                        setcookie('datareg', '', time() - 1);
                        throw new Exception('Invalid password');
                    }
                    return $respass;
                }
            } else {
                if ($this->pdo->quote($this->data['login']) === $v['login']) {
                    $respass = password_verify($this->data['pass'], $pass = substr($v['pass'], 1, -1));
                    if (!$respass) throw new Exception('Invalid password');
                    if (@isset($this->data['rmbr']) && $cookieaccess) {
                        setcookie('datareg', serialize(['login' => $this->data['login'], 'pass' => $pass]));
                    }
                    return $respass;
                }
            }
        }
        if (isset($_COOKIE['datareg'])) setcookie('datareg', '', time() - 1);
        throw new Exception('No such user!');
    }
    public function changeData(array $newdata, $dbname, $othr = 'login'){
        if(isset($this->data['pass'])) $this->dataChecking($dbname, false);
        if(@isset($newdata['pass'])) $newdata['pass'] = password_hash($newdata['pass'], $GLOBALS['dfmode']);
        if($othr = 'login') $othr = [$othr => $this->data['login']];
        return parent::__toUpdate($newdata, $dbname, $othr);
    }
}

class SignUp extends Authorization {
    private $data;
    public function __construct(array $data, array $dbdata, $code = false) {
        if ($code !== false and @$data['code'] != $code) throw new Exception('Invalid code');
        unset($data['code']);
        parent::__construct($dbdata);
        $data['pass'] = password_hash($data['pass'], $GLOBALS['dfmode']);
        if (is_uploaded_file($img = @$_FILES['img']['tmp_name'])) {
            $hash = sha1_file($img).'.'.pathinfo($_FILES['img']['name'])['extension'];
            move_uploaded_file($img, $GLOBALS['imgdir'].$hash);
            $data['img'] = $hash;
        }
        $this->data = $data;
    }
    public function toWrite($dbname){
        return parent::__toWrite($this->data, $dbname);
    }
    public static function checkDuplicate(array $data, $dbdata, $dbname) {
        
        $parent = new parent($dbdata);
        foreach ($data as $k => $v) {
            $data[$k] = $parent->pdo->quote($v);
        }
        $sqldata = $parent->__toSelect(array_keys($data), $dbname);
        $res = [];
        foreach ($sqldata as $v) {
            if(count($res) === count($data)) break;
            $res = array_keys(array_intersect($data, $v));
        }
        return $res;
    }
}
