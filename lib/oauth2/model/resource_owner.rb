module OAuth2
  module Model
    
    module ResourceOwner
      def self.included(klass)
        klass.has_many :oauth2_authorizations,
                       class_name: 'OAuth2::Model::Authorization',
                       as: :owner
      end
      
      def grant_access!(client, options = {})
        authorization = oauth2_authorizations.where(:client_id => client.id).first ||
                        Model::Authorization.create(:owner => self, :client => client)
        
        if scopes = options[:scopes]
          scopes = authorization.scopes + scopes
          authorization.update_attribute(:scope, scopes.entries.join(' '))
        end
        
        authorization
      end
    end
    
  end
end
