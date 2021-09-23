<?php
/**
 * Project escape-helper
 * Created by PhpStorm
 * User: 713uk13m <dev@nguyenanhung.com>
 * Copyright: 713uk13m <dev@nguyenanhung.com>
 * Date: 09/21/2021
 * Time: 00:00
 */

namespace nguyenanhung\Libraries\Escape;

/**
 * Trait Version
 *
 * @package   nguyenanhung\Libraries\Escape
 * @author    713uk13m <dev@nguyenanhung.com>
 * @copyright 713uk13m <dev@nguyenanhung.com>
 */
trait Version
{
    /**
     * Function getVersion
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 09/23/2021 35:58
     */
    public function getVersion(): string
    {
        return self::VERSION;
    }
}
