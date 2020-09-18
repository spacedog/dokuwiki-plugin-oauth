<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\Auth0;

class Auth0Adapter extends AbstractAdapter {

    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'user', 'email', 'name' and optional 'grps'
     *
     * @return array
     */
    public function getUser() {
        $JSON = new \JSON(JSON_LOOSE_TYPE);
        $data = array();

        $response = $this->oAuth->request('/userinfo');
        $result = $JSON->decode($response);


        $hlp = plugin_load('helper', 'oauth');
        $username_claim = "{$hlp->getConf('auth0-namespace')}username";
        $groups_claim   = "{$hlp->getConf('auth0-namespace')}groups";

        if( !empty($result[$username_claim]) )
        {
            $data['user'] = $result[$username_claim];
        }
        else
        {
            $data['user'] = isset($result['name']) ? $result['name'] : $result['email'];
        }
        $data['name'] = isset($result['name']) ? $result['name'] : $result['email'];
        $data['mail'] = $result['email'];
        $data['grps'] = isset($result[$groups_claim]) ? $result[$groups_claim] : [];

        return $data;
    }

    /**
     * Access to user and his email addresses
     *
     * @return array
     */
    public function getScope() {
        return array(Auth0::SCOPE_OPENID);
    }

}
