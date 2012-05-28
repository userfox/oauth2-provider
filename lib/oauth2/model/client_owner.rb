module OAuth2
  module Model
    
    module ClientOwner
      def self.included(klass)
        klass.has_many :oauth2_clients,
                       :class_name => 'OAuth2::Model::Client',
                       :as => :product
      end
    end
    
  end
end
